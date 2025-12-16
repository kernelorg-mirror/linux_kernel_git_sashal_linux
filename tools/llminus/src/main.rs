//! llminus - LLM-powered git conflict resolution tool

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use fastembed::{EmbeddingModel, InitOptions, TextEmbedding};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

const STORE_PATH: &str = ".llminus-resolutions.json";

#[derive(Parser)]
#[command(name = "llminus")]
#[command(about = "LLM-powered git conflict resolution tool")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Learn from historical merge conflict resolutions
    Learn {
        /// Git revision range (e.g., "v6.0..v6.1"). If not specified, learns from entire history.
        range: Option<String>,
    },
    /// Generate embeddings for stored resolutions (for RAG similarity search)
    Vectorize {
        /// Batch size for embedding generation (default: 64)
        #[arg(short, long, default_value = "64")]
        batch_size: usize,
    },
}

/// A single diff hunk representing a change region
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffHunk {
    /// Starting line in the original file
    pub start_line: u32,
    /// Number of lines in original
    pub original_count: u32,
    /// Number of lines in new version
    pub new_count: u32,
    /// The actual diff content (unified diff format lines)
    pub content: String,
}

/// A single file's conflict resolution within a merge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileResolution {
    pub file_path: String,
    pub file_type: String,      // Extension: "c", "h", "rs", etc.
    pub subsystem: String,      // Extracted from path: "drivers/gpu" -> "gpu"

    /// Changes from base to ours (what our branch did)
    pub ours_diff: Vec<DiffHunk>,
    /// Changes from base to theirs (what their branch did)
    pub theirs_diff: Vec<DiffHunk>,
    /// The final resolution diff (base to merge result)
    pub resolution_diff: Vec<DiffHunk>,
}

/// Format a section of diff hunks with a title header
fn format_hunk_section(title: &str, hunks: &[DiffHunk]) -> String {
    if hunks.is_empty() {
        return String::new();
    }
    let mut text = format!("=== {} ===\n", title);
    for h in hunks {
        text.push_str(&h.content);
        text.push('\n');
    }
    text.push('\n');
    text
}

impl FileResolution {
    /// Generate embedding text for this file's resolution
    pub fn to_embedding_text(&self) -> String {
        format!(
            "File: {}\n\n{}{}{}",
            self.file_path,
            format_hunk_section("OURS", &self.ours_diff),
            format_hunk_section("THEIRS", &self.theirs_diff),
            format_hunk_section("RESOLUTION", &self.resolution_diff),
        )
    }

    /// Compute a content hash for deduplication
    /// Two FileResolutions with identical file_path and diffs will have the same hash
    pub fn content_hash(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.file_path.hash(&mut hasher);
        for hunk in &self.ours_diff {
            hunk.content.hash(&mut hasher);
        }
        for hunk in &self.theirs_diff {
            hunk.content.hash(&mut hasher);
        }
        for hunk in &self.resolution_diff {
            hunk.content.hash(&mut hasher);
        }
        hasher.finish()
    }
}

/// A merge commit's conflict resolution (may contain multiple files)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeResolution {
    pub commit_hash: String,
    pub commit_summary: String,
    pub commit_date: String,     // ISO format
    pub author: String,

    /// All files that required manual conflict resolution in this merge
    pub files: Vec<FileResolution>,

    /// 384-dimensional embedding vector (BGE-small model) for the entire merge
    #[serde(skip_serializing_if = "Option::is_none")]
    pub embedding: Option<Vec<f32>>,
}

impl MergeResolution {
    /// Generate embedding text from all file resolutions
    pub fn to_embedding_text(&self) -> String {
        let mut text = format!("Merge: {}\n{}\n\n", self.commit_hash, self.commit_summary);
        for file in &self.files {
            text.push_str(&file.to_embedding_text());
            text.push_str("\n---\n\n");
        }
        text
    }
}

/// Collection of all learned resolutions
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ResolutionStore {
    pub version: u32,
    pub resolutions: Vec<MergeResolution>,
    /// Commits we've processed (including those with only duplicate files)
    #[serde(default)]
    pub processed_commits: Vec<String>,
}

impl ResolutionStore {
    pub fn load(path: &Path) -> Result<Self> {
        if path.exists() {
            let content = std::fs::read_to_string(path)?;
            Ok(serde_json::from_str(&content)?)
        } else {
            Ok(Self { version: 2, resolutions: Vec::new(), processed_commits: Vec::new() })
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        // Use compact JSON for faster serialization (use jq to pretty-print if needed)
        let content = serde_json::to_string(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }
}

/// Run a git command and return stdout
fn git(args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .args(args)
        .output()
        .context("Failed to run git")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git {} failed: {}", args.join(" "), stderr);
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Run a git command, return stdout, allow failure
fn git_allow_fail(args: &[&str]) -> Option<String> {
    Command::new("git")
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
}

/// Check we're in a git repository
fn check_repo() -> Result<()> {
    git(&["rev-parse", "--git-dir"])?;
    Ok(())
}

/// Get merge commits in range (or all history)
fn get_merge_commits(range: Option<&str>) -> Result<Vec<String>> {
    let args: Vec<&str> = match range {
        Some(r) => vec!["log", "--merges", "--format=%H", r],
        None => vec!["log", "--merges", "--format=%H"],
    };

    let output = git(&args)?;
    Ok(output.lines().map(|s| s.to_string()).collect())
}

/// Metadata extracted from a git commit
struct CommitMetadata {
    summary: String,
    date: String,
    author: String,
}

/// Get commit metadata
fn get_commit_metadata(hash: &str) -> CommitMetadata {
    let format = git_allow_fail(&["log", "-1", "--format=%s%n%aI%n%an <%ae>", hash])
        .unwrap_or_default();
    let mut lines = format.lines();
    CommitMetadata {
        summary: lines.next().unwrap_or_default().to_string(),
        date: lines.next().unwrap_or_default().to_string(),
        author: lines.next().unwrap_or_default().to_string(),
    }
}

/// Get parent commits of a merge
fn get_parents(hash: &str) -> Result<Vec<String>> {
    let output = git(&["log", "-1", "--format=%P", hash])?;
    Ok(output.split_whitespace().map(|s| s.to_string()).collect())
}

/// Get merge base between two commits
fn get_merge_base(commit1: &str, commit2: &str) -> Option<String> {
    git_allow_fail(&["merge-base", commit1, commit2])
        .map(|s| s.trim().to_string())
}

/// Extract file type from path
fn get_file_type(path: &str) -> String {
    Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_string()
}

/// Extract subsystem from path (first or second directory component)
fn get_subsystem(path: &str) -> String {
    let parts: Vec<&str> = path.split('/').collect();
    match parts.first() {
        Some(&"drivers") | Some(&"fs") | Some(&"net") | Some(&"arch") | Some(&"sound") => {
            parts.get(1).unwrap_or(&"").to_string()
        }
        Some(first) => first.to_string(),
        None => String::new(),
    }
}

/// Get unified diff between two commits for a specific file
fn get_diff(from: &str, to: &str, file: &str) -> Option<String> {
    git_allow_fail(&["diff", "-U3", from, to, "--", file])
}

/// Get file content at a specific commit
fn get_file_at_commit(commit: &str, path: &str) -> Option<String> {
    git_allow_fail(&["show", &format!("{}:{}", commit, path)])
}

/// Parse unified diff into hunks
fn parse_diff_hunks(diff: &str) -> Vec<DiffHunk> {
    let mut hunks = Vec::new();
    let mut current_hunk: Option<(u32, u32, u32, Vec<String>)> = None;

    for line in diff.lines() {
        if line.starts_with("@@") {
            // Save previous hunk
            if let Some((start, orig_count, new_count, lines)) = current_hunk.take() {
                hunks.push(DiffHunk {
                    start_line: start,
                    original_count: orig_count,
                    new_count: new_count,
                    content: lines.join("\n"),
                });
            }

            // Parse hunk header: @@ -start,count +start,count @@
            if let Some(header) = parse_hunk_header(line) {
                current_hunk = Some((header.0, header.1, header.2, vec![line.to_string()]));
            }
        } else if current_hunk.is_some() && (line.starts_with('+') || line.starts_with('-') || line.starts_with(' ')) {
            if let Some((_, _, _, ref mut lines)) = current_hunk {
                lines.push(line.to_string());
            }
        }
    }

    // Save last hunk
    if let Some((start, orig_count, new_count, lines)) = current_hunk {
        hunks.push(DiffHunk {
            start_line: start,
            original_count: orig_count,
            new_count: new_count,
            content: lines.join("\n"),
        });
    }

    hunks
}

/// Parse a hunk header like "@@ -10,5 +10,7 @@" -> (start, orig_count, new_count)
fn parse_hunk_header(line: &str) -> Option<(u32, u32, u32)> {
    let line = line.trim_start_matches("@@ ");
    let parts: Vec<&str> = line.split(' ').collect();
    if parts.len() < 2 {
        return None;
    }

    let parse_range = |s: &str| -> (u32, u32) {
        let s = s.trim_start_matches(['-', '+']);
        if let Some((start, count)) = s.split_once(',') {
            (start.parse().unwrap_or(1), count.parse().unwrap_or(1))
        } else {
            (s.parse().unwrap_or(1), 1)
        }
    };

    let (orig_start, orig_count) = parse_range(parts[0]);
    let (_, new_count) = parse_range(parts[1]);

    Some((orig_start, orig_count, new_count))
}

/// Find files modified in both branches
fn find_modified_in_both(parent1: &str, parent2: &str, base: &str) -> Result<Vec<String>> {
    let changed1 = git_allow_fail(&["diff", "--name-only", base, parent1])
        .unwrap_or_default();
    let changed2 = git_allow_fail(&["diff", "--name-only", base, parent2])
        .unwrap_or_default();

    let files1: HashSet<_> = changed1.lines().collect();
    let files2: HashSet<_> = changed2.lines().collect();

    Ok(files1.intersection(&files2).map(|s| s.to_string()).collect())
}

/// Extract conflict resolutions from a merge commit
/// Returns None if no manual conflict resolution was needed
fn extract_resolution(hash: &str) -> Result<Option<MergeResolution>> {
    let parents = get_parents(hash)?;
    if parents.len() < 2 {
        return Ok(None);
    }

    let parent1 = &parents[0];
    let parent2 = &parents[1];

    let base = match get_merge_base(parent1, parent2) {
        Some(b) => b,
        None => return Ok(None),
    };

    let meta = get_commit_metadata(hash);
    let modified = find_modified_in_both(parent1, parent2, &base)?;

    let mut files = Vec::new();

    for file_path in modified {
        // Get diffs: base->ours, base->theirs, base->resolution
        let ours_diff_raw = get_diff(&base, parent1, &file_path);
        let theirs_diff_raw = get_diff(&base, parent2, &file_path);
        let resolution_diff_raw = get_diff(&base, hash, &file_path);

        // Parse into hunks
        let ours_hunks = ours_diff_raw.as_ref().map(|d| parse_diff_hunks(d)).unwrap_or_default();
        let theirs_hunks = theirs_diff_raw.as_ref().map(|d| parse_diff_hunks(d)).unwrap_or_default();
        let resolution_hunks = resolution_diff_raw.as_ref().map(|d| parse_diff_hunks(d)).unwrap_or_default();

        // Skip if no actual changes
        if ours_hunks.is_empty() && theirs_hunks.is_empty() {
            continue;
        }

        // Skip if ours == theirs (no real conflict)
        if ours_diff_raw == theirs_diff_raw {
            continue;
        }

        // Only keep if resolution differs from BOTH parents (manual merge required)
        let ours_content = get_file_at_commit(parent1, &file_path);
        let theirs_content = get_file_at_commit(parent2, &file_path);
        let resolution_content = get_file_at_commit(hash, &file_path);

        if resolution_content == ours_content || resolution_content == theirs_content {
            continue; // Trivial resolution, no manual merge needed
        }

        files.push(FileResolution {
            file_path: file_path.clone(),
            file_type: get_file_type(&file_path),
            subsystem: get_subsystem(&file_path),
            ours_diff: ours_hunks,
            theirs_diff: theirs_hunks,
            resolution_diff: resolution_hunks,
        });
    }

    // Only return if there were actual conflicts
    if files.is_empty() {
        return Ok(None);
    }

    Ok(Some(MergeResolution {
        commit_hash: hash.to_string(),
        commit_summary: meta.summary,
        commit_date: meta.date,
        author: meta.author,
        files,
        embedding: None,
    }))
}

fn learn(range: Option<&str>) -> Result<()> {
    check_repo()?;

    let store_path = Path::new(STORE_PATH);
    let mut store = ResolutionStore::load(store_path)?;
    store.version = 3;  // Upgrade version (grouped by commit)

    // First, deduplicate existing store
    let mut seen_hashes: HashSet<u64> = HashSet::new();
    let mut existing_duplicates_removed = 0usize;

    store.resolutions = store.resolutions
        .into_iter()
        .filter_map(|mut resolution| {
            let original_len = resolution.files.len();
            resolution.files.retain(|f| {
                let hash = f.content_hash();
                if seen_hashes.contains(&hash) {
                    false // Duplicate, remove
                } else {
                    seen_hashes.insert(hash);
                    true // Unique, keep
                }
            });
            existing_duplicates_removed += original_len - resolution.files.len();

            if resolution.files.is_empty() {
                None
            } else {
                Some(resolution)
            }
        })
        .collect();

    if existing_duplicates_removed > 0 {
        println!("Deduplicated existing store: removed {} duplicate files",
                 existing_duplicates_removed);
    }

    // Track existing commits to avoid re-analyzing (includes commits with only duplicate files)
    let mut processed_commits: HashSet<_> = store.processed_commits.iter().cloned().collect();
    // Also include commits from resolutions (for backwards compatibility with old stores)
    for r in &store.resolutions {
        processed_commits.insert(r.commit_hash.clone());
    }

    println!("Existing store: {} commits, {} unique file resolutions, {} total processed",
             store.resolutions.len(), seen_hashes.len(), processed_commits.len());

    let merge_commits = get_merge_commits(range)?;
    let total_commits = merge_commits.len();

    // Filter to only new commits
    let new_commits: Vec<_> = merge_commits
        .into_iter()
        .filter(|h| !processed_commits.contains(h))
        .collect();

    println!("Found {} merge commits ({} new to analyze)", total_commits, new_commits.len());

    if new_commits.is_empty() {
        if existing_duplicates_removed > 0 {
            store.save(store_path)?;
            println!("Store saved after deduplication.");
        } else {
            println!("No new commits to process.");
        }
        return Ok(());
    }

    // Configure thread pool for git subprocesses
    let num_threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(8);

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build()
        .context("Failed to build thread pool")?;

    println!("Using {} threads", num_threads);

    // Progress counter
    let processed = AtomicUsize::new(0);
    let total_new = new_commits.len();

    // Process commits in parallel
    let resolutions: Vec<MergeResolution> = pool.install(|| {
        new_commits
            .par_iter()
            .filter_map(|hash| {
                let count = processed.fetch_add(1, Ordering::Relaxed) + 1;
                if count % 100 == 0 || count == total_new {
                    eprintln!("  Progress: {}/{}", count, total_new);
                }

                match extract_resolution(hash) {
                    Ok(Some(resolution)) => Some(resolution),
                    Ok(None) => None,
                    Err(e) => {
                        eprintln!("Warning: Failed to analyze {}: {}", &hash[..12], e);
                        None
                    }
                }
            })
            .collect()
    });

    // Count files before deduplication
    let total_files_before: usize = resolutions.iter().map(|r| r.files.len()).sum();
    let commits_with_conflicts_before = resolutions.len();

    // Filter out duplicate file resolutions using the same hash set
    let mut new_duplicates_skipped = 0usize;

    let deduped_resolutions: Vec<MergeResolution> = resolutions
        .into_iter()
        .filter_map(|mut resolution| {
            let original_len = resolution.files.len();
            resolution.files.retain(|f| {
                let hash = f.content_hash();
                if seen_hashes.contains(&hash) {
                    false // Duplicate, skip
                } else {
                    seen_hashes.insert(hash);
                    true // Unique, keep
                }
            });
            new_duplicates_skipped += original_len - resolution.files.len();

            // Only keep commits that still have at least one unique file
            if resolution.files.is_empty() {
                None
            } else {
                Some(resolution)
            }
        })
        .collect();

    // Aggregate results
    let commits_stored = deduped_resolutions.len();
    let files_stored: usize = deduped_resolutions.iter().map(|r| r.files.len()).sum();

    // Track all processed commits (including those with only duplicate files)
    for commit in &new_commits {
        processed_commits.insert(commit.clone());
    }
    store.processed_commits = processed_commits.into_iter().collect();

    store.resolutions.extend(deduped_resolutions);
    store.save(store_path)?;

    // Calculate approximate size
    let json_size = std::fs::metadata(store_path).map(|m| m.len()).unwrap_or(0);
    let total_stored_files: usize = store.resolutions.iter().map(|r| r.files.len()).sum();

    println!("\nResults:");
    println!("  Merge commits analyzed: {}", total_commits);
    println!("  Commits with conflicts: {}", commits_with_conflicts_before);
    println!("  Files found: {}", total_files_before);
    if existing_duplicates_removed > 0 {
        println!("  Existing duplicates removed: {}", existing_duplicates_removed);
    }
    println!("  New duplicate files skipped: {}", new_duplicates_skipped);
    println!("  New commits stored: {}", commits_stored);
    println!("  New files stored: {}", files_stored);
    println!("  Total in store: {} commits, {} files", store.resolutions.len(), total_stored_files);
    println!("  Output size: {:.2} MB", json_size as f64 / 1024.0 / 1024.0);
    println!("\nResolutions saved to: {}", store_path.display());

    Ok(())
}

/// Compute cosine similarity between two vectors
fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }

    let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let norm_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let norm_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();

    if norm_a == 0.0 || norm_b == 0.0 {
        return 0.0;
    }

    dot / (norm_a * norm_b)
}

/// Initialize the BGE-small embedding model
fn init_embedding_model() -> Result<TextEmbedding> {
    TextEmbedding::try_new(
        InitOptions::new(EmbeddingModel::BGESmallENV15)
            .with_show_download_progress(true),
    ).context("Failed to initialize embedding model")
}

fn vectorize(batch_size: usize) -> Result<()> {
    let store_path = Path::new(STORE_PATH);

    if !store_path.exists() {
        bail!("No resolutions found. Run 'llminus learn' first.");
    }

    let mut store = ResolutionStore::load(store_path)?;

    // Count how many need embeddings
    let need_embedding: Vec<usize> = store
        .resolutions
        .iter()
        .enumerate()
        .filter(|(_, r)| r.embedding.is_none())
        .map(|(i, _)| i)
        .collect();

    if need_embedding.is_empty() {
        println!("All {} resolutions already have embeddings.", store.resolutions.len());
        return Ok(());
    }

    println!("Found {} resolutions needing embeddings", need_embedding.len());
    println!("Initializing embedding model (BGE-small-en, ~33MB download on first run)...");

    // Initialize the embedding model
    let mut model = init_embedding_model()?;

    println!("Model loaded. Generating embeddings...\n");

    // Process in batches
    let total_batches = (need_embedding.len() + batch_size - 1) / batch_size;

    for (batch_num, chunk) in need_embedding.chunks(batch_size).enumerate() {
        // Collect texts for this batch
        let texts: Vec<String> = chunk
            .iter()
            .map(|&i| store.resolutions[i].to_embedding_text())
            .collect();

        // Generate embeddings
        let embeddings = model
            .embed(texts, None)
            .context("Failed to generate embeddings")?;

        // Assign embeddings back to resolutions
        for (j, &idx) in chunk.iter().enumerate() {
            store.resolutions[idx].embedding = Some(embeddings[j].clone());
        }

        // Progress report
        let done = (batch_num + 1) * batch_size.min(chunk.len());
        let pct = (done as f64 / need_embedding.len() as f64 * 100.0).min(100.0);
        println!(
            "  Batch {}/{}: {:.1}% ({}/{})",
            batch_num + 1,
            total_batches,
            pct,
            done.min(need_embedding.len()),
            need_embedding.len()
        );

        // Save after each batch (incremental progress)
        store.save(store_path)?;
    }

    // Final stats
    let json_size = std::fs::metadata(store_path).map(|m| m.len()).unwrap_or(0);
    let with_embeddings = store.resolutions.iter().filter(|r| r.embedding.is_some()).count();

    println!("\nResults:");
    println!("  Total resolutions: {}", store.resolutions.len());
    println!("  With embeddings: {}", with_embeddings);
    println!("  Embedding dimensions: 384");
    println!("  Output size: {:.2} MB", json_size as f64 / 1024.0 / 1024.0);
    println!("\nEmbeddings saved to: {}", store_path.display());

    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Learn { range } => learn(range.as_deref()),
        Commands::Vectorize { batch_size } => vectorize(batch_size),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn verify_cli() {
        Cli::command().debug_assert();
    }

    #[test]
    fn test_learn_command_parses() {
        let cli = Cli::try_parse_from(["llminus", "learn"]).unwrap();
        match cli.command {
            Commands::Learn { range } => assert!(range.is_none()),
            _ => panic!("Expected Learn command"),
        }
    }

    #[test]
    fn test_learn_command_with_range() {
        let cli = Cli::try_parse_from(["llminus", "learn", "v6.0..v6.1"]).unwrap();
        match cli.command {
            Commands::Learn { range } => assert_eq!(range, Some("v6.0..v6.1".to_string())),
            _ => panic!("Expected Learn command"),
        }
    }

    #[test]
    fn test_vectorize_command_parses() {
        let cli = Cli::try_parse_from(["llminus", "vectorize"]).unwrap();
        match cli.command {
            Commands::Vectorize { batch_size } => assert_eq!(batch_size, 64),
            _ => panic!("Expected Vectorize command"),
        }
    }

    #[test]
    fn test_vectorize_command_with_batch_size() {
        let cli = Cli::try_parse_from(["llminus", "vectorize", "-b", "128"]).unwrap();
        match cli.command {
            Commands::Vectorize { batch_size } => assert_eq!(batch_size, 128),
            _ => panic!("Expected Vectorize command"),
        }
    }

    #[test]
    fn test_cosine_similarity() {
        // Identical vectors should have similarity 1.0
        let a = vec![1.0, 0.0, 0.0];
        let b = vec![1.0, 0.0, 0.0];
        assert!((cosine_similarity(&a, &b) - 1.0).abs() < 0.0001);

        // Orthogonal vectors should have similarity 0.0
        let a = vec![1.0, 0.0, 0.0];
        let b = vec![0.0, 1.0, 0.0];
        assert!((cosine_similarity(&a, &b) - 0.0).abs() < 0.0001);

        // Opposite vectors should have similarity -1.0
        let a = vec![1.0, 0.0, 0.0];
        let b = vec![-1.0, 0.0, 0.0];
        assert!((cosine_similarity(&a, &b) - (-1.0)).abs() < 0.0001);

        // Different length vectors return 0
        let a = vec![1.0, 0.0];
        let b = vec![1.0, 0.0, 0.0];
        assert_eq!(cosine_similarity(&a, &b), 0.0);
    }

    #[test]
    fn test_get_file_type() {
        assert_eq!(get_file_type("foo/bar.c"), "c");
        assert_eq!(get_file_type("foo/bar.rs"), "rs");
        assert_eq!(get_file_type("Makefile"), "");
        assert_eq!(get_file_type("include/linux/module.h"), "h");
    }

    #[test]
    fn test_get_subsystem() {
        assert_eq!(get_subsystem("drivers/gpu/drm/foo.c"), "gpu");
        assert_eq!(get_subsystem("fs/ext4/inode.c"), "ext4");
        assert_eq!(get_subsystem("kernel/sched/core.c"), "kernel");
        assert_eq!(get_subsystem("net/ipv4/tcp.c"), "ipv4");
        assert_eq!(get_subsystem("mm/memory.c"), "mm");
    }

    #[test]
    fn test_parse_hunk_header() {
        assert_eq!(parse_hunk_header("@@ -10,5 +10,7 @@"), Some((10, 5, 7)));
        assert_eq!(parse_hunk_header("@@ -1 +1,2 @@"), Some((1, 1, 2)));
        assert_eq!(parse_hunk_header("@@ -100,20 +105,25 @@ func"), Some((100, 20, 25)));
    }

    #[test]
    fn test_parse_diff_hunks() {
        let diff = r#"diff --git a/file.c b/file.c
index 123..456 789
--- a/file.c
+++ b/file.c
@@ -10,3 +10,4 @@ context
 unchanged
-removed
+added
+another
"#;
        let hunks = parse_diff_hunks(diff);
        assert_eq!(hunks.len(), 1);
        assert_eq!(hunks[0].start_line, 10);
        assert!(hunks[0].content.contains("-removed"));
        assert!(hunks[0].content.contains("+added"));
    }

    fn init_test_repo() -> TempDir {
        let dir = TempDir::new().unwrap();
        Command::new("git")
            .args(["init"])
            .current_dir(dir.path())
            .output()
            .unwrap();
        Command::new("git")
            .args(["config", "user.email", "test@test.com"])
            .current_dir(dir.path())
            .output()
            .unwrap();
        Command::new("git")
            .args(["config", "user.name", "Test"])
            .current_dir(dir.path())
            .output()
            .unwrap();
        dir
    }

    fn create_commit(dir: &TempDir, filename: &str, content: &str, msg: &str) {
        fs::write(dir.path().join(filename), content).unwrap();
        Command::new("git")
            .args(["add", filename])
            .current_dir(dir.path())
            .output()
            .unwrap();
        Command::new("git")
            .args(["commit", "-m", msg])
            .current_dir(dir.path())
            .output()
            .unwrap();
    }

    fn create_branch(dir: &TempDir, name: &str) {
        Command::new("git")
            .args(["checkout", "-b", name])
            .current_dir(dir.path())
            .output()
            .unwrap();
    }

    fn checkout(dir: &TempDir, name: &str) {
        Command::new("git")
            .args(["checkout", name])
            .current_dir(dir.path())
            .output()
            .unwrap();
    }

    fn merge(dir: &TempDir, branch: &str, msg: &str) {
        Command::new("git")
            .args(["merge", "--no-ff", "-m", msg, branch])
            .current_dir(dir.path())
            .output()
            .unwrap();
    }

    #[test]
    fn test_resolution_store_roundtrip() {
        let dir = TempDir::new().unwrap();
        let store_path = dir.path().join("resolutions.json");

        let mut store = ResolutionStore { version: 3, resolutions: Vec::new() };
        store.resolutions.push(MergeResolution {
            commit_hash: "abc123".to_string(),
            commit_summary: "Test merge".to_string(),
            commit_date: "2024-01-15T10:00:00Z".to_string(),
            author: "Test <test@test.com>".to_string(),
            files: vec![FileResolution {
                file_path: "test.c".to_string(),
                file_type: "c".to_string(),
                subsystem: "test".to_string(),
                ours_diff: vec![DiffHunk {
                    start_line: 10,
                    original_count: 3,
                    new_count: 4,
                    content: "@@ -10,3 +10,4 @@\n-old\n+new".to_string(),
                }],
                theirs_diff: vec![],
                resolution_diff: vec![],
            }],
            embedding: None,
        });

        store.save(&store_path).unwrap();
        let loaded = ResolutionStore::load(&store_path).unwrap();

        assert_eq!(loaded.version, 3);
        assert_eq!(loaded.resolutions.len(), 1);
        assert_eq!(loaded.resolutions[0].commit_hash, "abc123");
        assert_eq!(loaded.resolutions[0].files.len(), 1);
        assert_eq!(loaded.resolutions[0].files[0].file_path, "test.c");
        assert_eq!(loaded.resolutions[0].files[0].file_type, "c");

        // Test embedding text generation for merge
        let embedding = loaded.resolutions[0].to_embedding_text();
        assert!(embedding.contains("Merge: abc123"));
        assert!(embedding.contains("File: test.c"));
        assert!(embedding.contains("=== OURS ==="));
        assert!(embedding.contains("-old"));
        assert!(embedding.contains("+new"));
    }

    #[test]
    fn test_git_in_repo() {
        let dir = init_test_repo();
        std::env::set_current_dir(dir.path()).unwrap();
        create_commit(&dir, "file.txt", "initial", "initial commit");
        let result = check_repo();
        assert!(result.is_ok());
    }

    #[test]
    fn test_get_merge_commits() {
        let dir = init_test_repo();
        std::env::set_current_dir(dir.path()).unwrap();

        create_commit(&dir, "file.txt", "initial", "initial commit");
        create_branch(&dir, "feature");
        create_commit(&dir, "feature.txt", "feature", "feature commit");
        checkout(&dir, "master");
        create_commit(&dir, "main.txt", "main", "main commit");
        merge(&dir, "feature", "Merge feature");

        let merges = get_merge_commits(None).unwrap();
        assert_eq!(merges.len(), 1);
    }
}
