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

/// Default maximum tokens for prompt (conservative for broad provider compatibility)
/// Most providers support at least 128K; we use 100K as a safe default.
const DEFAULT_MAX_TOKENS: usize = 100_000;

/// Approximate characters per token (for English text)
const CHARS_PER_TOKEN: usize = 4;

/// Estimate the number of tokens in a text string
fn estimate_tokens(text: &str) -> usize {
    text.len() / CHARS_PER_TOKEN
}

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
    /// Find similar historical conflict resolutions for current conflicts
    Find {
        /// Number of similar resolutions to show (default: 1)
        #[arg(default_value = "1")]
        n: usize,
    },
    /// Resolve current conflicts using an LLM
    Resolve {
        /// Command to invoke. The prompt will be passed via stdin.
        command: String,
        /// Maximum tokens for prompt (reduces RAG examples if exceeded)
        #[arg(short, long, default_value_t = DEFAULT_MAX_TOKENS)]
        max_tokens: usize,
    },
    /// Pull a kernel patch/pull request from lore.kernel.org and merge it
    Pull {
        /// Message ID from lore.kernel.org (e.g., "98b74397-05bc-dbee-cab4-3f40d643eaac@kernel.org")
        message_id: String,
        /// Command to invoke for LLM assistance
        #[arg(short, long, default_value = "llm")]
        command: String,
        /// Maximum tokens for prompt (reduces RAG examples if exceeded)
        #[arg(long, default_value_t = DEFAULT_MAX_TOKENS)]
        max_tokens: usize,
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

/// A file with active conflict markers
#[derive(Debug)]
struct ConflictFile {
    path: String,
    ours_content: String,
    theirs_content: String,
    base_content: Option<String>,
}

impl ConflictFile {
    /// Generate embedding text for this conflict
    fn to_embedding_text(&self) -> String {
        let mut text = format!("File: {}\n\n", self.path);

        text.push_str("=== OURS ===\n");
        text.push_str(&self.ours_content);
        text.push_str("\n\n");

        text.push_str("=== THEIRS ===\n");
        text.push_str(&self.theirs_content);
        text.push('\n');

        if let Some(ref base) = self.base_content {
            text.push_str("\n=== BASE ===\n");
            text.push_str(base);
            text.push('\n');
        }

        text
    }
}

/// Get list of files with unmerged conflicts
fn get_conflicted_files() -> Result<Vec<String>> {
    // git diff --name-only --diff-filter=U shows unmerged files
    let output = git(&["diff", "--name-only", "--diff-filter=U"])?;
    Ok(output.lines().map(|s| s.to_string()).filter(|s| !s.is_empty()).collect())
}

/// State machine for parsing conflict markers
enum ConflictParseState {
    Outside,
    InOurs,
    InBase,
    InTheirs,
}

/// Append a line to a string, adding newline separator if non-empty
fn append_line(s: &mut String, line: &str) {
    if !s.is_empty() {
        s.push('\n');
    }
    s.push_str(line);
}

/// Parse conflict markers from a file and extract ours/theirs/base content
fn parse_conflict_file(path: &str) -> Result<Vec<ConflictFile>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path))?;

    let mut conflicts = Vec::new();
    let mut state = ConflictParseState::Outside;
    let mut current_ours = String::new();
    let mut current_theirs = String::new();
    let mut current_base: Option<String> = None;

    for line in content.lines() {
        if line.starts_with("<<<<<<<") {
            state = ConflictParseState::InOurs;
            current_ours.clear();
            current_theirs.clear();
            current_base = None;
        } else if line.starts_with("|||||||") {
            // diff3 style - base content follows
            state = ConflictParseState::InBase;
            current_base = Some(String::new());
        } else if line.starts_with("=======") {
            state = ConflictParseState::InTheirs;
        } else if line.starts_with(">>>>>>>") {
            // End of conflict block - save it
            conflicts.push(ConflictFile {
                path: path.to_string(),
                ours_content: std::mem::take(&mut current_ours),
                theirs_content: std::mem::take(&mut current_theirs),
                base_content: current_base.take(),
            });
            state = ConflictParseState::Outside;
        } else {
            match state {
                ConflictParseState::InOurs => append_line(&mut current_ours, line),
                ConflictParseState::InBase => {
                    if let Some(ref mut base) = current_base {
                        append_line(base, line);
                    }
                }
                ConflictParseState::InTheirs => append_line(&mut current_theirs, line),
                ConflictParseState::Outside => {}
            }
        }
    }

    Ok(conflicts)
}

/// Result of a similarity search
#[derive(Clone)]
struct SimilarResolution {
    resolution: MergeResolution,
    similarity: f32,
}

/// Find similar resolutions (shared logic for find and resolve)
fn find_similar_resolutions(n: usize) -> Result<(Vec<ConflictFile>, Vec<SimilarResolution>)> {
    check_repo()?;

    let store_path = Path::new(STORE_PATH);
    if !store_path.exists() {
        bail!("No resolutions database found. Run 'llminus learn' first.");
    }

    // Find current conflicts
    let conflict_paths = get_conflicted_files()?;
    if conflict_paths.is_empty() {
        bail!("No conflicts detected. Run this command when you have active merge conflicts.");
    }

    // Parse all conflict regions
    let mut all_conflicts = Vec::new();
    for path in &conflict_paths {
        if let Ok(conflicts) = parse_conflict_file(path) {
            all_conflicts.extend(conflicts);
        }
    }

    if all_conflicts.is_empty() {
        bail!("Could not parse any conflict markers from the conflicted files.");
    }

    // Load the resolution store
    let store = ResolutionStore::load(store_path)?;
    let with_embeddings: Vec<_> = store.resolutions.iter()
        .filter(|r| r.embedding.is_some())
        .collect();

    if with_embeddings.is_empty() {
        bail!("No embeddings in database. Run 'llminus vectorize' first.");
    }

    // Initialize embedding model
    let mut model = init_embedding_model()?;

    // Generate embedding for current conflicts
    let conflict_text: String = all_conflicts.iter()
        .map(|c| c.to_embedding_text())
        .collect::<Vec<_>>()
        .join("\n---\n\n");

    let query_embeddings = model
        .embed(vec![conflict_text], None)
        .context("Failed to generate embedding for current conflict")?;
    let query_embedding = &query_embeddings[0];

    // Compute similarities and take top N (clone resolutions to own them)
    let mut similarities: Vec<_> = with_embeddings.iter()
        .map(|r| {
            let sim = cosine_similarity(query_embedding, r.embedding.as_ref().unwrap());
            (r, sim)
        })
        .collect();

    similarities.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    let top_n: Vec<SimilarResolution> = similarities.into_iter()
        .take(n)
        .map(|(r, sim)| SimilarResolution {
            resolution: (*r).clone(),
            similarity: sim,
        })
        .collect();

    Ok((all_conflicts, top_n))
}

fn find(n: usize) -> Result<()> {
    // Use find_similar_resolutions for core search logic
    let (_conflicts, top_n) = find_similar_resolutions(n)?;

    // Display results
    println!("\n{}", "=".repeat(80));
    println!("Top {} similar historical conflict resolution(s):", top_n.len());
    println!("{}", "=".repeat(80));

    for (i, result) in top_n.iter().enumerate() {
        let r = &result.resolution;
        println!("\n{}. [similarity: {:.4}]", i + 1, result.similarity);
        println!("   Commit: {}", r.commit_hash);
        println!("   Summary: {}", r.commit_summary);
        println!("   Author: {}", r.author);
        println!("   Date: {}", r.commit_date);
        println!("   Files ({}):", r.files.len());
        for file in &r.files {
            println!("     - {} ({})", file.file_path, file.subsystem);
        }

        // Show the resolution diffs for each file
        println!("\n   Resolution details:");
        for file in &r.files {
            println!("   --- {} ---", file.file_path);
            if !file.resolution_diff.is_empty() {
                for hunk in &file.resolution_diff {
                    // Indent and print the diff
                    for line in hunk.content.lines() {
                        println!("   {}", line);
                    }
                }
            } else {
                println!("   (no diff hunks recorded)");
            }
        }
        println!();
    }

    // Provide git show command for easy access
    if let Some(top) = top_n.first() {
        println!("{}", "-".repeat(80));
        println!("To see the full commit:");
        println!("  git show {}", top.resolution.commit_hash);
    }

    Ok(())
}

/// Context about the current merge operation
#[derive(Debug, Default)]
struct MergeContext {
    /// The branch/tag/ref being merged (from MERGE_HEAD or MERGE_MSG)
    merge_source: Option<String>,
    /// The target branch (HEAD)
    head_branch: Option<String>,
    /// The merge message (from .git/MERGE_MSG)
    merge_message: Option<String>,
}

/// Extract context about the current merge operation
fn get_merge_context() -> MergeContext {
    let mut ctx = MergeContext::default();

    // Get current branch name
    ctx.head_branch = git_allow_fail(&["rev-parse", "--abbrev-ref", "HEAD"])
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && s != "HEAD");

    // Try to read MERGE_MSG for merge context
    if let Ok(merge_msg) = std::fs::read_to_string(".git/MERGE_MSG") {
        ctx.merge_message = Some(merge_msg.clone());

        // Parse merge source from MERGE_MSG
        // Common formats:
        // "Merge branch 'feature-branch'"
        // "Merge tag 'v6.1'"
        // "Merge remote-tracking branch 'origin/main'"
        // "Merge commit 'abc123'"
        let first_line = merge_msg.lines().next().unwrap_or("");
        if let Some(source) = parse_merge_source(first_line) {
            ctx.merge_source = Some(source);
        }
    }

    // If no merge source found from MERGE_MSG, try to describe MERGE_HEAD
    if ctx.merge_source.is_none() {
        // Try to get a tag name for MERGE_HEAD
        if let Some(tag) = git_allow_fail(&["describe", "--tags", "--exact-match", "MERGE_HEAD"]) {
            ctx.merge_source = Some(tag.trim().to_string());
        } else if let Some(branch) = git_allow_fail(&["name-rev", "--name-only", "MERGE_HEAD"]) {
            let branch = branch.trim();
            if !branch.is_empty() && branch != "undefined" {
                ctx.merge_source = Some(branch.to_string());
            }
        }
    }

    ctx
}

/// Parse merge source from a merge message first line
fn parse_merge_source(line: &str) -> Option<String> {
    // "Merge branch 'feature'" -> "feature"
    // "Merge tag 'v6.1'" -> "v6.1"
    // "Merge remote-tracking branch 'origin/main'" -> "origin/main"
    // "Merge commit 'abc123'" -> "abc123"

    let line = line.trim();

    // Look for quoted source
    if let Some(start) = line.find('\'') {
        if let Some(end) = line[start + 1..].find('\'') {
            return Some(line[start + 1..start + 1 + end].to_string());
        }
    }

    // Look for "Merge X into Y" pattern without quotes
    if line.starts_with("Merge ") {
        let rest = &line[6..];
        // Skip "branch ", "tag ", "commit ", "remote-tracking branch "
        let rest = rest
            .strip_prefix("remote-tracking branch ")
            .or_else(|| rest.strip_prefix("branch "))
            .or_else(|| rest.strip_prefix("tag "))
            .or_else(|| rest.strip_prefix("commit "))
            .unwrap_or(rest);

        // Take until " into " or end of line
        if let Some(into_pos) = rest.find(" into ") {
            return Some(rest[..into_pos].trim().to_string());
        }
        let word = rest.split_whitespace().next()?;
        if !word.is_empty() {
            return Some(word.to_string());
        }
    }

    None
}

/// Information parsed from a lore.kernel.org pull request email
#[derive(Debug, Default)]
#[allow(dead_code)]
struct PullRequest {
    /// Message ID
    message_id: String,
    /// Subject line of the email
    subject: String,
    /// Author name and email
    from: String,
    /// Date of the email
    date: String,
    /// Git repository URL to pull from
    git_url: String,
    /// Git ref (tag or branch) to pull
    git_ref: String,
    /// The full raw email body (LLM extracts summary and conflict instructions from this)
    body: String,
}

/// Fetch raw email from lore.kernel.org
fn fetch_lore_email(message_id: &str) -> Result<String> {
    // Clean up message ID (remove < > if present)
    let clean_id = message_id
        .trim_start_matches('<')
        .trim_end_matches('>')
        .trim();

    let url = format!("https://lore.kernel.org/all/{}/raw", clean_id);
    println!("Fetching: {}", url);

    let response = ureq::get(&url)
        .call()
        .with_context(|| format!("Failed to fetch {}", url))?;

    if response.status() != 200 {
        bail!("HTTP error {}", response.status());
    }

    response.into_body().read_to_string()
        .context("Failed to read response body")
}

/// Parse email headers from raw email text
fn parse_email_headers(raw: &str) -> (String, String, String, String, &str) {
    let mut from = String::new();
    let mut subject = String::new();
    let mut date = String::new();
    let mut message_id = String::new();

    // Find the blank line separating headers from body
    let (headers_section, body) = raw.split_once("\n\n")
        .unwrap_or((raw, ""));

    // Parse headers (handle multi-line headers)
    let mut current_header = String::new();
    let mut current_value = String::new();

    for line in headers_section.lines() {
        if line.starts_with(' ') || line.starts_with('\t') {
            // Continuation of previous header
            current_value.push(' ');
            current_value.push_str(line.trim());
        } else if let Some((name, value)) = line.split_once(':') {
            // New header - save previous if any
            if !current_header.is_empty() {
                match current_header.to_lowercase().as_str() {
                    "from" => from = current_value.clone(),
                    "subject" => subject = current_value.clone(),
                    "date" => date = current_value.clone(),
                    "message-id" => message_id = current_value.clone(),
                    _ => {}
                }
            }
            current_header = name.to_string();
            current_value = value.trim().to_string();
        }
    }

    // Don't forget last header
    if !current_header.is_empty() {
        match current_header.to_lowercase().as_str() {
            "from" => from = current_value,
            "subject" => subject = current_value,
            "date" => date = current_value,
            "message-id" => message_id = current_value,
            _ => {}
        }
    }

    (from, subject, date, message_id, body)
}

/// Extract git pull URL and ref from email body
fn extract_git_info(body: &str) -> Option<(String, String)> {
    // Look for patterns like:
    // "git://git.kernel.org/pub/scm/linux/kernel/git/riscv/linux tags/riscv-for-linus-6.19-mw2"
    // "https://git.kernel.org/pub/scm/linux/kernel/git/foo/bar.git branch-name"

    for line in body.lines() {
        let line = line.trim();

        // Skip empty lines and common non-URL prefixes
        if line.is_empty() {
            continue;
        }

        // Check for git:// or https:// URLs
        let url_start = if let Some(pos) = line.find("git://") {
            pos
        } else if let Some(pos) = line.find("https://git.") {
            pos
        } else {
            continue;
        };

        let url_part = &line[url_start..];

        // Split into URL and ref
        let parts: Vec<&str> = url_part.split_whitespace().collect();
        if parts.len() >= 2 {
            let url = parts[0].to_string();
            let git_ref = parts[1].to_string();

            // Validate it looks like a kernel git URL
            if url.contains("kernel.org") || url.contains("git.") {
                return Some((url, git_ref));
            }
        }
    }

    None
}

/// Use LLM to extract the maintainer's summary from the email body
/// Returns None if extraction fails (caller can fall back to other methods)
fn extract_summary_with_llm(body: &str, command: &str) -> Option<String> {
    use std::io::Write;
    use std::process::Stdio;

    let prompt = format!(r#"Extract ONLY the technical summary from this kernel pull request email.
The summary describes what changes are included (usually as bullet points).
Do NOT include:
- Personal messages to Linus
- Git URLs or repository information
- Merge/conflict resolution instructions
- Diffstat or file change listings
- Sign-offs or signatures

Output ONLY the summary text, nothing else. No preamble, no explanation.

Email body:
{}
"#, body);

    let parts: Vec<&str> = command.split_whitespace().collect();
    if parts.is_empty() {
        return None;
    }

    println!("Extracting summary from pull request...");

    let mut child = match Command::new(parts[0])
        .args(&parts[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn() {
            Ok(c) => c,
            Err(_) => return None,
        };

    if let Some(mut stdin) = child.stdin.take() {
        if stdin.write_all(prompt.as_bytes()).is_err() {
            return None;
        }
    }

    let output = match child.wait_with_output() {
        Ok(o) => o,
        Err(_) => return None,
    };

    if !output.status.success() {
        return None;
    }

    let summary = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if summary.is_empty() {
        None
    } else {
        Some(summary)
    }
}

/// Parse a pull request email from lore.kernel.org
fn parse_pull_request(message_id: &str, raw: &str) -> Result<PullRequest> {
    let (from, subject, date, parsed_id, body) = parse_email_headers(raw);

    let (git_url, git_ref) = extract_git_info(body)
        .ok_or_else(|| anyhow::anyhow!("Could not find git repository URL in email"))?;

    Ok(PullRequest {
        message_id: if parsed_id.is_empty() { message_id.to_string() } else { parsed_id },
        subject,
        from,
        date,
        git_url,
        git_ref,
        body: body.to_string(),
    })
}

/// Execute git pull and return whether there are conflicts
fn git_pull(url: &str, git_ref: &str) -> Result<bool> {
    println!("Executing: git pull {} {}", url, git_ref);

    let output = Command::new("git")
        .args(["pull", url, git_ref])
        .output()
        .context("Failed to run git pull")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if !stdout.is_empty() {
        println!("{}", stdout);
    }
    if !stderr.is_empty() {
        eprintln!("{}", stderr);
    }

    // Check if there are conflicts
    if output.status.success() {
        return Ok(false); // No conflicts
    }

    // Check for merge conflicts specifically
    let conflict_markers = ["CONFLICT", "Automatic merge failed", "fix conflicts"];
    let output_text = format!("{}{}", stdout, stderr);

    for marker in conflict_markers {
        if output_text.contains(marker) {
            return Ok(true); // Has conflicts
        }
    }

    // Some other error
    bail!("git pull failed: {}", stderr);
}

/// Check if there are unmerged files (active merge conflicts)
fn has_merge_conflicts() -> bool {
    get_conflicted_files()
        .map(|files| !files.is_empty())
        .unwrap_or(false)
}

/// Build a merge commit message using the pull request information, summary, and resolution
fn build_merge_commit_message(pull_req: &PullRequest, summary: &str, resolution: &str) -> String {
    let mut msg = String::new();

    // Use the subject line as the merge message header
    if !pull_req.subject.is_empty() {
        // Clean up subject - remove [GIT PULL] prefix if present
        let subject = pull_req.subject
            .replace("[GIT PULL]", "")
            .replace("[git pull]", "")
            .trim()
            .to_string();
        msg.push_str(&format!("Merge {} {}\n", pull_req.git_ref, &subject));
    } else {
        msg.push_str(&format!("Merge {}\n", pull_req.git_ref));
    }
    msg.push('\n');

    // Add maintainer's summary (extracted by LLM)
    if !summary.is_empty() {
        msg.push_str(summary);
        msg.push_str("\n\n");
    }

    // Add resolution explanation (written by LLM during conflict resolution)
    if !resolution.is_empty() {
        msg.push_str("Merge conflict resolution:\n\n");
        msg.push_str(resolution);
        msg.push_str("\n\n");
    }

    // Add link to lore
    msg.push_str(&format!("Link: https://lore.kernel.org/all/{}/\n",
        pull_req.message_id.trim_start_matches('<').trim_end_matches('>')));

    msg
}

/// Get current conflicts from the working directory
/// Returns an empty Vec if there are no conflicts (for build-only issues)
fn get_current_conflicts() -> Result<Vec<ConflictFile>> {
    check_repo()?;

    // Find current conflicts
    let conflict_paths = get_conflicted_files()?;
    if conflict_paths.is_empty() {
        // No conflicts - this is fine, might be a build-only issue
        return Ok(Vec::new());
    }

    // Parse all conflict regions
    let mut all_conflicts = Vec::new();
    for path in &conflict_paths {
        if let Ok(conflicts) = parse_conflict_file(path) {
            all_conflicts.extend(conflicts);
        }
    }

    Ok(all_conflicts)
}

/// Try to find similar resolutions, returns empty vec if no database or embeddings
fn try_find_similar_resolutions(n: usize, conflicts: &[ConflictFile]) -> Vec<SimilarResolution> {
    let store_path = Path::new(STORE_PATH);
    if !store_path.exists() {
        return Vec::new();
    }

    let store = match ResolutionStore::load(store_path) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    let with_embeddings: Vec<_> = store.resolutions.iter()
        .filter(|r| r.embedding.is_some())
        .collect();

    if with_embeddings.is_empty() {
        return Vec::new();
    }

    // Initialize embedding model
    let mut model = match init_embedding_model() {
        Ok(m) => m,
        Err(_) => return Vec::new(),
    };

    // Generate embedding for current conflicts
    let conflict_text: String = conflicts.iter()
        .map(|c| c.to_embedding_text())
        .collect::<Vec<_>>()
        .join("\n---\n\n");

    let query_embeddings = match model.embed(vec![conflict_text], None) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };
    let query_embedding = &query_embeddings[0];

    // Compute similarities and take top N
    let mut similarities: Vec<_> = with_embeddings.iter()
        .map(|r| {
            let sim = cosine_similarity(query_embedding, r.embedding.as_ref().unwrap());
            (r, sim)
        })
        .collect();

    similarities.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    similarities.into_iter()
        .take(n)
        .map(|(r, sim)| SimilarResolution {
            resolution: (*r).clone(),
            similarity: sim,
        })
        .collect()
}

/// Represents the result of a build test
struct BuildTestResult {
    success: bool,
    output: String,
}

/// Run a build test and capture any warnings/errors
/// Returns the build output (stderr from `stable build log`)
///
/// NOTE: The build system requires all changes to be committed.
/// The LLM prompts instruct the model to commit before running build tests.
/// We don't enforce this in code because the shell script may legitimately
/// pass staged changes to llminus for the LLM to handle.
fn run_build_test() -> BuildTestResult {
    use std::process::Stdio;

    println!("Running build test: stable build log");

    let result = Command::new("stable")
        .args(["build", "log"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();

    match result {
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();

            // Combine stderr (warnings/errors) with any stdout for full picture
            let combined = if stderr.is_empty() {
                stdout
            } else if stdout.is_empty() {
                stderr
            } else {
                format!("{}\n{}", stderr, stdout)
            };

            // Check for actual build issues - look for warning/error patterns
            let has_issues = combined.lines().any(|line| {
                let lower = line.to_lowercase();
                lower.contains("error:") || lower.contains("warning:")
                    || lower.contains("error[") || lower.contains("undefined reference")
                    || lower.contains("fatal error") || lower.contains("make[")
            });

            BuildTestResult {
                success: output.status.success() && !has_issues,
                output: combined.trim().to_string(),
            }
        }
        Err(e) => BuildTestResult {
            success: false,
            output: format!("Failed to run build test: {}", e),
        },
    }
}

/// Build an LLM prompt for fixing build errors (when no merge conflicts exist)
fn build_fix_prompt(build_output: &str, merge_ctx: &MergeContext) -> String {
    let mut prompt = String::new();

    // Header with high-stakes framing (matching the existing style)
    prompt.push_str("# Linux Kernel Build Issue Resolution\n\n");
    prompt.push_str("You are acting as an experienced kernel maintainer. A merge completed without ");
    prompt.push_str("textual conflicts, but the build test revealed warnings or errors that need to be fixed.\n\n");

    prompt.push_str("**Important:** Incorrect fixes have historically introduced subtle bugs ");
    prompt.push_str("that affected millions of users and took months to diagnose. A fix that ");
    prompt.push_str("silences a warning but has semantic errors is worse than no fix at all.\n\n");

    prompt.push_str("Take the time to fully understand the build failure before attempting ");
    prompt.push_str("any fix. If after investigation you're not confident, say so - it's ");
    prompt.push_str("better to escalate to a human than to introduce a subtle bug.\n\n");

    // Merge context
    prompt.push_str("## Merge Context\n\n");
    if let Some(ref source) = merge_ctx.merge_source {
        prompt.push_str(&format!("**Merged:** `{}`\n", source));
    }
    if let Some(ref head) = merge_ctx.head_branch {
        prompt.push_str(&format!("**Into:** `{}`\n", head));
    }
    prompt.push_str("\nThe merge itself completed without textual conflicts, but the build has issues.\n\n");

    // Build output
    prompt.push_str("## Build Output\n\n");
    prompt.push_str("The following warnings/errors were produced by `stable build log` (allmodconfig build):\n\n");
    prompt.push_str("```\n");
    prompt.push_str(build_output);
    prompt.push_str("\n```\n\n");

    // Investigation requirement (matching existing style)
    prompt.push_str("## Investigation Required\n\n");
    prompt.push_str("Before attempting any fix, you must conduct thorough research. ");
    prompt.push_str("Rushing to fix without understanding is how subtle bugs get introduced. ");
    prompt.push_str("Work through each phase below IN ORDER and document your findings.\n\n");

    // Phase 1: Search lore.kernel.org
    prompt.push_str("### Phase 1: Search lore.kernel.org for Guidance (DO THIS FIRST)\n\n");
    prompt.push_str("**CRITICAL:** Before doing ANY other research, search lore.kernel.org for existing guidance.\n");
    prompt.push_str("Maintainers often discuss build issues when they know they will occur after merges.\n\n");

    if let Some(ref source) = merge_ctx.merge_source {
        prompt.push_str(&format!("1. **Search for the merge itself:** `{}`\n", source));
        prompt.push_str(&format!("   - URL: `https://lore.kernel.org/all/?q={}`\n", source.replace('/', "%2F")));
    }
    prompt.push_str("2. **Search for similar build issues:**\n");
    prompt.push_str("   - Search for the specific error message or warning text\n");
    prompt.push_str("   - `\"build error\"` + subsystem name\n\n");

    // Phase 2: Understand the context
    prompt.push_str("### Phase 2: Understand the Context\n\n");
    prompt.push_str("- **Identify the affected files** from the error/warning messages\n");
    prompt.push_str("- **What subsystem is this?** Read the file and nearby files to understand its purpose.\n");
    prompt.push_str("- **Who maintains it?** Check `git log --oneline -20` for recent authors.\n\n");

    // Phase 3: Trace history
    prompt.push_str("### Phase 3: Trace the History\n\n");
    prompt.push_str("**Understand what changed:**\n");
    prompt.push_str("- Run `git log --oneline HEAD~5..HEAD -- <file>` to see recent changes\n");
    prompt.push_str("- Use `git show <commit>` to read the full commit messages\n");
    prompt.push_str("- Check both sides of the merge: `git diff HEAD^1..HEAD^2 -- <file>`\n\n");

    prompt.push_str("**Common causes of post-merge build issues:**\n");
    prompt.push_str("- Missing includes when code from one branch uses types/functions defined in another\n");
    prompt.push_str("- Renamed or removed functions/macros that the merged code references\n");
    prompt.push_str("- Conflicting definitions (same symbol defined differently in merged branches)\n");
    prompt.push_str("- Changes to function signatures that weren't propagated to all callers\n");
    prompt.push_str("- Linker script or section changes that affect symbol placement\n\n");

    // Resolution
    prompt.push_str("## Resolution\n\n");
    prompt.push_str("Once you understand the issue:\n\n");
    prompt.push_str("1. Fix the build issues in the affected files\n");
    prompt.push_str("2. Stage your changes with `git add`\n");
    prompt.push_str("3. **COMMIT BEFORE BUILD TEST:** Create a temporary commit to test the build:\n");
    prompt.push_str("   ```bash\n");
    prompt.push_str("   git commit -m \"WIP: testing build fix\"\n");
    prompt.push_str("   ```\n");
    prompt.push_str("   The build system requires all changes to be committed to test them.\n");
    prompt.push_str("4. **MANDATORY BUILD TEST:** Run `stable build log` to verify the fix\n");
    prompt.push_str("5. If the build fails, try to fix the issues, amend the commit, and re-run the build test\n");
    prompt.push_str("6. **ALWAYS UNDO TEMPORARY COMMIT:** Whether build succeeded or failed, you MUST undo the temporary commit:\n");
    prompt.push_str("   ```bash\n");
    prompt.push_str("   git reset --soft HEAD~1\n");
    prompt.push_str("   ```\n");
    prompt.push_str("   This is MANDATORY - the calling script expects staged changes, not a committed state.\n");
    prompt.push_str("   If the build still fails after your best effort, report the failure but STILL do the soft reset.\n\n");

    // If uncertain
    prompt.push_str("## If Uncertain\n\n");
    prompt.push_str("If after investigation you're still uncertain about the correct fix:\n\n");
    prompt.push_str("- Explain what you've learned and what remains unclear\n");
    prompt.push_str("- Describe the possible fixes you see and their tradeoffs\n");
    prompt.push_str("- Recommend whether a human maintainer should review\n\n");
    prompt.push_str("It's better to flag uncertainty than to silently introduce a bug.\n\n");

    // Tools available
    prompt.push_str("## Tools Available\n\n");
    prompt.push_str("You can use these to investigate:\n\n");
    prompt.push_str("```bash\n");
    prompt.push_str("# View recent changes to the affected file\n");
    prompt.push_str("git log --oneline HEAD~10..HEAD -- <file>\n");
    prompt.push_str("\n");
    prompt.push_str("# Compare the merge parents\n");
    prompt.push_str("git diff HEAD^1..HEAD^2 -- <file>\n");
    prompt.push_str("\n");
    prompt.push_str("# Understand a specific commit\n");
    prompt.push_str("git show <hash>\n");
    prompt.push_str("\n");
    prompt.push_str("# Re-run the build test\n");
    prompt.push_str("stable build log\n");
    prompt.push_str("```\n");

    prompt
}

/// Build the LLM prompt for conflict resolution
fn build_resolve_prompt(
    conflicts: &[ConflictFile],
    similar: &[SimilarResolution],
    merge_ctx: &MergeContext,
    pull_req: Option<&PullRequest>,
) -> String {
    let mut prompt = String::new();

    // Header with high-stakes framing
    if pull_req.is_some() {
        prompt.push_str("# Linux Kernel Pull Request Merge with Conflict Resolution\n\n");
        prompt.push_str("You are acting as an experienced kernel maintainer resolving conflicts ");
        prompt.push_str("from a pull request submission on lore.kernel.org.\n\n");
    } else {
        prompt.push_str("# Linux Kernel Merge Conflict Resolution\n\n");
        prompt.push_str("You are acting as an experienced kernel maintainer resolving a merge conflict.\n\n");
    }
    prompt.push_str("**Important:** Incorrect merge resolutions have historically introduced subtle bugs ");
    prompt.push_str("that affected millions of users and took months to diagnose. A resolution that ");
    prompt.push_str("compiles but has semantic errors is worse than no resolution at all.\n\n");

    // Pull request specific: critical evaluation note
    if pull_req.is_some() {
        prompt.push_str("**CRITICAL:** You have access to the pull request email which may contain ");
        prompt.push_str("conflict resolution instructions from the maintainer. Use these as guidance, ");
        prompt.push_str("but ALWAYS evaluate them critically - there may be better, cleaner, or more ");
        prompt.push_str("efficient solutions than what was suggested.\n\n");
    } else {
        prompt.push_str("Take the time to fully understand both sides of the conflict before attempting ");
        prompt.push_str("any resolution. If after investigation you're not confident, say so - it's ");
        prompt.push_str("better to escalate to a human than to introduce a subtle bug.\n\n");
    }

    // Pull request information (if present)
    if let Some(pr) = pull_req {
        prompt.push_str("## Pull Request Information\n\n");
        prompt.push_str(&format!("- **Subject:** {}\n", pr.subject));
        prompt.push_str(&format!("- **From:** {}\n", pr.from));
        prompt.push_str(&format!("- **Date:** {}\n", pr.date));
        prompt.push_str(&format!("- **Git URL:** {} {}\n", pr.git_url, pr.git_ref));
        prompt.push_str(&format!("- **Message ID:** {}\n\n", pr.message_id));

        // Full email body - LLM will understand summary and conflict instructions from this
        prompt.push_str("### Pull Request Email\n\n");
        prompt.push_str("Read this email carefully. It contains the maintainer's description of the changes ");
        prompt.push_str("and may include conflict resolution instructions. Evaluate any suggested ");
        prompt.push_str("resolutions critically - there may be cleaner or more efficient solutions.\n\n");
        prompt.push_str("```\n");
        prompt.push_str(&pr.body);
        prompt.push_str("\n```\n\n");
    }

    // Merge context
    prompt.push_str("## Merge Context\n\n");
    if let Some(ref source) = merge_ctx.merge_source {
        prompt.push_str(&format!("**Merging:** `{}`\n", source));
    }
    if let Some(ref head) = merge_ctx.head_branch {
        prompt.push_str(&format!("**Into:** `{}`\n", head));
    }
    if let Some(ref msg) = merge_ctx.merge_message {
        let first_line = msg.lines().next().unwrap_or("");
        prompt.push_str(&format!("**Merge message:** {}\n", first_line));
    }
    prompt.push_str("\n");

    // Current conflicts
    prompt.push_str("## Current Conflicts\n\n");

    for conflict in conflicts {
        prompt.push_str(&format!("### File: {}\n\n", conflict.path));
        prompt.push_str("**Our version (HEAD):**\n```\n");
        prompt.push_str(&conflict.ours_content);
        prompt.push_str("\n```\n\n");
        prompt.push_str("**Their version (being merged):**\n```\n");
        prompt.push_str(&conflict.theirs_content);
        prompt.push_str("\n```\n\n");
        if let Some(ref base) = conflict.base_content {
            prompt.push_str("**Base version (common ancestor):**\n```\n");
            prompt.push_str(base);
            prompt.push_str("\n```\n\n");
        }
    }

    // Similar historical resolutions (only if available)
    if !similar.is_empty() {
        prompt.push_str("## Similar Historical Resolutions\n\n");
        prompt.push_str("These conflicts were previously resolved in the Linux kernel. Use `git show <hash>` ");
        prompt.push_str("to examine the full commit message and context - maintainers often explain ");
        prompt.push_str("their resolution rationale there.\n\n");

        for (i, result) in similar.iter().enumerate() {
            let r = &result.resolution;
            prompt.push_str(&format!("### Historical Resolution {} (similarity: {:.1}%)\n\n", i + 1, result.similarity * 100.0));
            prompt.push_str(&format!("- **Commit:** `{}`\n", r.commit_hash));
            prompt.push_str(&format!("- **Summary:** {}\n", r.commit_summary));
            prompt.push_str(&format!("- **Author:** {}\n", r.author));
            prompt.push_str(&format!("- **Date:** {}\n", r.commit_date));
            prompt.push_str(&format!("- **Files:** {}\n\n", r.files.iter().map(|f| f.file_path.as_str()).collect::<Vec<_>>().join(", ")));

            for file in &r.files {
                prompt.push_str(&format!("#### {}\n\n", file.file_path));

                if !file.ours_diff.is_empty() {
                    prompt.push_str("**Ours changed:**\n```diff\n");
                    for hunk in &file.ours_diff {
                        prompt.push_str(&hunk.content);
                        prompt.push_str("\n");
                    }
                    prompt.push_str("```\n\n");
                }

                if !file.theirs_diff.is_empty() {
                    prompt.push_str("**Theirs changed:**\n```diff\n");
                    for hunk in &file.theirs_diff {
                        prompt.push_str(&hunk.content);
                        prompt.push_str("\n");
                    }
                    prompt.push_str("```\n\n");
                }

                if !file.resolution_diff.is_empty() {
                    prompt.push_str("**Final resolution:**\n```diff\n");
                    for hunk in &file.resolution_diff {
                        prompt.push_str(&hunk.content);
                        prompt.push_str("\n");
                    }
                    prompt.push_str("```\n\n");
                }
            }
        }
    }

    // Investigation requirement
    prompt.push_str("## Investigation Required\n\n");
    prompt.push_str("Before attempting any resolution, you must conduct thorough research. ");
    prompt.push_str("Rushing to resolve without understanding is how subtle bugs get introduced. ");
    prompt.push_str("Work through each phase below IN ORDER and document your findings.\n\n");

    // Phase 1: Search lore.kernel.org
    prompt.push_str("### Phase 1: Search lore.kernel.org for Maintainer Guidance (DO THIS FIRST)\n\n");
    prompt.push_str("**CRITICAL:** Before doing ANY other research, search lore.kernel.org for existing guidance.\n");
    prompt.push_str("Maintainers often post merge resolution instructions when they know conflicts will occur.\n\n");

    if let Some(ref source) = merge_ctx.merge_source {
        prompt.push_str(&format!("1. **Search for the merge itself:** `{}`\n", source));
        prompt.push_str(&format!("   - URL: `https://lore.kernel.org/all/?q={}`\n", source.replace('/', "%2F")));
    }
    prompt.push_str("2. **Search for conflict discussions:**\n");
    prompt.push_str("   - `\"merge conflict\"` + subsystem name\n");
    prompt.push_str("   - `\"conflicts with\"` + branch/tag name\n\n");

    // Phase 2: Context
    prompt.push_str("### Phase 2: Understand the Context\n\n");
    prompt.push_str("- **What subsystem is this?** Read the file and nearby files to understand its purpose.\n");
    prompt.push_str("- **Who maintains it?** Check `git log --oneline -20` for recent authors.\n");
    prompt.push_str("- **What's the file's role?** Is it a driver, core subsystem, header, config?\n\n");

    // Phase 3: Trace history
    prompt.push_str("### Phase 3: Trace Each Side's History\n\n");
    prompt.push_str("**For 'ours' (HEAD):**\n");
    prompt.push_str("- Run `git log --oneline HEAD -- <file>` to see recent changes\n");
    prompt.push_str("- Find the commit that introduced our version of the conflicted code\n");
    prompt.push_str("- Run `git show <commit>` to read the full commit message\n\n");
    prompt.push_str("**For 'theirs' (MERGE_HEAD):**\n");
    prompt.push_str("- Run `git log --oneline MERGE_HEAD -- <file>` to see their changes\n");
    prompt.push_str("- Find the commit that introduced their version\n");
    prompt.push_str("- Run `git show <commit>` to read the full commit message\n\n");

    // Resolution
    prompt.push_str("## Resolution\n\n");
    prompt.push_str("Once you understand the conflict:\n\n");
    prompt.push_str("1. Edit the conflicted files to produce the correct merged result\n");
    prompt.push_str("2. Remove all conflict markers (`<<<<<<<`, `=======`, `>>>>>>>`)\n");
    prompt.push_str("3. Stage the resolved files with `git add`\n");
    prompt.push_str("4. **COMMIT BEFORE BUILD TEST:** Create a temporary commit to test the build:\n");
    prompt.push_str("   ```bash\n");
    prompt.push_str("   git commit -m \"WIP: testing merge resolution\"\n");
    prompt.push_str("   ```\n");
    prompt.push_str("   The build system requires all changes to be committed to test them.\n");
    prompt.push_str("5. **MANDATORY BUILD TEST:** Verify the build succeeds with no warnings or errors:\n");
    prompt.push_str("   ```bash\n");
    prompt.push_str("   stable build log\n");
    prompt.push_str("   ```\n");
    prompt.push_str("   This runs an allmodconfig build and outputs only warnings/errors to stderr.\n");
    prompt.push_str("   Review the output for ANY warnings or errors. If the build fails or produces warnings,\n");
    prompt.push_str("   you MUST try to fix them, amend the commit, and re-run the build test.\n");
    prompt.push_str("6. **ALWAYS UNDO TEMPORARY COMMIT:** Whether build succeeded or failed, you MUST undo the temporary commit:\n");
    prompt.push_str("   ```bash\n");
    prompt.push_str("   git reset --soft HEAD~1\n");
    prompt.push_str("   ```\n");
    prompt.push_str("   This is MANDATORY - the calling script expects staged changes, not a committed state.\n");
    prompt.push_str("   If the build still fails after your best effort, report the failure but STILL do the soft reset.\n");
    if pull_req.is_some() {
        prompt.push_str("7. **IMPORTANT:** Write a detailed explanation of your resolution to `.git/LLMINUS_RESOLUTION`\n");
        prompt.push_str("   This file should contain:\n");
        prompt.push_str("   - A summary of each conflict and how you resolved it\n");
        prompt.push_str("   - The reasoning behind your choices\n");
        prompt.push_str("   - Any improvements you made over suggested resolutions\n");
        prompt.push_str("   This will be included in the merge commit message.\n\n");
    }

    // If uncertain
    prompt.push_str("## If Uncertain\n\n");
    prompt.push_str("If after investigation you're still uncertain about the correct resolution:\n\n");
    prompt.push_str("- Explain what you've learned and what remains unclear\n");
    prompt.push_str("- Describe the possible resolutions you see and their tradeoffs\n");
    prompt.push_str("- Recommend whether a human maintainer should review\n\n");
    prompt.push_str("It's better to flag uncertainty than to silently introduce a bug.\n\n");

    // Tools available
    prompt.push_str("## Tools Available\n\n");
    prompt.push_str("You can use these to investigate:\n\n");
    prompt.push_str("```bash\n");
    if !similar.is_empty() {
        prompt.push_str("# Examine historical resolution commits\n");
        for result in similar {
            prompt.push_str(&format!("git show {}\n", result.resolution.commit_hash));
        }
        prompt.push_str("\n");
    }
    prompt.push_str("# Understand merge parents\n");
    prompt.push_str("git show <hash>^1  # ours\n");
    prompt.push_str("git show <hash>^2  # theirs\n");
    prompt.push_str("```\n");

    prompt
}

fn resolve(command: &str, max_tokens: usize) -> Result<()> {
    // Get merge context (what branch/tag is being merged)
    let merge_ctx = get_merge_context();
    if let Some(ref source) = merge_ctx.merge_source {
        println!("Merging: {}", source);
    }
    if let Some(ref head) = merge_ctx.head_branch {
        println!("Into: {}", head);
    }

    // Get current conflicts first
    let conflicts = get_current_conflicts()?;

    if conflicts.is_empty() {
        // No textual conflicts - check for build issues instead
        println!("No textual conflicts detected.");
        println!("Running build test to check for merge-related build issues...\n");

        let build_result = run_build_test();

        if build_result.success {
            println!("Build test passed. No issues to resolve.");
            return Ok(());
        }

        // Build failed - invoke LLM to fix the issues
        println!("\nBuild test failed! Invoking LLM to resolve build issues...\n");
        let prompt = build_fix_prompt(&build_result.output, &merge_ctx);
        return invoke_llm(command, &prompt);
    }

    println!("Found {} conflict(s)", conflicts.len());

    // Try to find similar historical resolutions (gracefully handles missing database)
    println!("Looking for similar historical conflicts...");
    let all_similar = try_find_similar_resolutions(3, &conflicts);

    if all_similar.is_empty() {
        println!("No historical resolution database found (run 'llminus learn' and 'llminus vectorize' to build one)");
        println!("Proceeding without historical examples...");
    } else {
        println!("Found {} similar historical resolutions", all_similar.len());
    }

    // Build the prompt with adaptive RAG example reduction
    let mut similar = all_similar.clone();
    let mut prompt = build_resolve_prompt(&conflicts, &similar, &merge_ctx, None);
    let mut tokens = estimate_tokens(&prompt);

    // Reduce RAG examples until we're under the token limit
    while tokens > max_tokens && !similar.is_empty() {
        let original_count = all_similar.len();
        similar.pop(); // Remove the least similar (last) example
        prompt = build_resolve_prompt(&conflicts, &similar, &merge_ctx, None);
        tokens = estimate_tokens(&prompt);

        if similar.len() < original_count {
            println!(
                "Reduced RAG examples from {} to {} to fit token limit (~{} tokens, limit: {})",
                original_count,
                similar.len(),
                tokens,
                max_tokens
            );
        }
    }

    if tokens > max_tokens {
        println!(
            "Warning: Prompt still exceeds token limit (~{} tokens, limit: {}) even without RAG examples",
            tokens, max_tokens
        );
    }

    invoke_llm(command, &prompt)
}

/// Invoke an LLM command with a prompt via stdin
fn invoke_llm(command: &str, prompt: &str) -> Result<()> {
    use std::io::Write;
    use std::process::Stdio;

    let tokens = estimate_tokens(prompt);
    println!("Invoking: {} (prompt: {} bytes, ~{} tokens)", command, prompt.len(), tokens);
    println!("{}", "=".repeat(80));

    // Parse command (handle arguments)
    let parts: Vec<&str> = command.split_whitespace().collect();
    if parts.is_empty() {
        bail!("Empty command specified");
    }

    let cmd = parts[0];
    let args = &parts[1..];

    // Spawn the command
    let mut child = Command::new(cmd)
        .args(args)
        .stdin(Stdio::piped())
        .spawn()
        .with_context(|| format!("Failed to spawn command: {}", command))?;

    // Write prompt to stdin
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(prompt.as_bytes())
            .context("Failed to write prompt to command stdin")?;
    }

    // Wait for completion
    let status = child.wait().context("Failed to wait for command")?;

    println!("{}", "=".repeat(80));

    if status.success() {
        println!("\nCommand completed successfully.");
    } else {
        eprintln!("\nCommand exited with status: {}", status);
    }

    Ok(())
}

/// Pull a kernel pull request from lore.kernel.org
fn pull(message_id: &str, command: &str, max_tokens: usize) -> Result<()> {
    check_repo()?;

    // Step 1: Fetch and parse the pull request email
    println!("=== Fetching Pull Request ===\n");
    let raw_email = fetch_lore_email(message_id)?;
    let pull_req = parse_pull_request(message_id, &raw_email)?;

    println!("Subject: {}", pull_req.subject);
    println!("From: {}", pull_req.from);
    println!("Date: {}", pull_req.date);
    println!("Git URL: {} {}", pull_req.git_url, pull_req.git_ref);

    // Step 2: Execute git pull
    println!("\n=== Executing Git Pull ===\n");
    let has_conflicts = git_pull(&pull_req.git_url, &pull_req.git_ref)?;

    if !has_conflicts {
        // No conflicts - merge succeeded automatically
        println!("\n=== Merge Completed Successfully ===");
        println!("No conflicts detected. The merge was completed automatically.");
        return Ok(());
    }

    // Step 3: Handle conflicts
    println!("\n=== Merge Conflicts Detected ===\n");

    // Get merge context
    let merge_ctx = get_merge_context();

    // Parse the conflicts
    let conflicts = get_current_conflicts()?;
    println!("Found {} conflict region(s) to resolve", conflicts.len());

    // Try to find similar historical resolutions
    println!("Looking for similar historical conflicts...");
    let all_similar = try_find_similar_resolutions(3, &conflicts);

    if all_similar.is_empty() {
        println!("No historical resolution database found (this is optional)");
    } else {
        println!("Found {} similar historical resolutions", all_similar.len());
    }

    // Build the prompt with adaptive RAG example reduction
    let mut similar = all_similar.clone();
    let mut prompt = build_resolve_prompt(&conflicts, &similar, &merge_ctx, Some(&pull_req));
    let mut tokens = estimate_tokens(&prompt);

    // Reduce RAG examples until we're under the token limit
    while tokens > max_tokens && !similar.is_empty() {
        let original_count = all_similar.len();
        similar.pop(); // Remove the least similar (last) example
        prompt = build_resolve_prompt(&conflicts, &similar, &merge_ctx, Some(&pull_req));
        tokens = estimate_tokens(&prompt);

        if similar.len() < original_count {
            println!(
                "Reduced RAG examples from {} to {} to fit token limit (~{} tokens, limit: {})",
                original_count,
                similar.len(),
                tokens,
                max_tokens
            );
        }
    }

    if tokens > max_tokens {
        println!(
            "Warning: Prompt still exceeds token limit (~{} tokens, limit: {}) even without RAG examples",
            tokens, max_tokens
        );
    }

    println!("\n=== Invoking LLM for Conflict Resolution ===");
    invoke_llm(command, &prompt)?;

    // Step 5: Check if conflicts are resolved
    if has_merge_conflicts() {
        println!("\nWarning: Conflicts still remain in the working directory.");
        println!("Please resolve any remaining conflicts manually and commit.");
        return Ok(());
    }

    // Step 6: Commit the merge with pull request information
    println!("\n=== Committing Merge ===\n");

    // Extract summary using LLM (falls back to empty if it fails)
    let summary = extract_summary_with_llm(&pull_req.body, command)
        .unwrap_or_else(|| {
            println!("Note: Could not extract summary automatically");
            String::new()
        });

    // Read resolution explanation written by LLM
    let resolution = std::fs::read_to_string(".git/LLMINUS_RESOLUTION")
        .unwrap_or_else(|_| {
            println!("Note: No resolution explanation found in .git/LLMINUS_RESOLUTION");
            String::new()
        });

    // Clean up the resolution file
    let _ = std::fs::remove_file(".git/LLMINUS_RESOLUTION");

    let commit_msg = build_merge_commit_message(&pull_req, &summary, &resolution);
    println!("Commit message:\n{}", commit_msg);

    // Create a temporary file for the commit message (to handle multi-line)
    let commit_result = Command::new("git")
        .args(["commit", "-m", &commit_msg])
        .output()
        .context("Failed to run git commit")?;

    if commit_result.status.success() {
        println!("\n=== Merge Committed Successfully ===");
        let stdout = String::from_utf8_lossy(&commit_result.stdout);
        if !stdout.is_empty() {
            println!("{}", stdout);
        }
    } else {
        let stderr = String::from_utf8_lossy(&commit_result.stderr);
        eprintln!("Commit failed: {}", stderr);
        bail!("Failed to commit merge");
    }

    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Learn { range } => learn(range.as_deref()),
        Commands::Vectorize { batch_size } => vectorize(batch_size),
        Commands::Find { n } => find(n),
        Commands::Resolve { command, max_tokens } => resolve(&command, max_tokens),
        Commands::Pull { message_id, command, max_tokens } => pull(&message_id, &command, max_tokens),
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
    fn test_find_command_parses() {
        let cli = Cli::try_parse_from(["llminus", "find"]).unwrap();
        match cli.command {
            Commands::Find { n } => assert_eq!(n, 1),
            _ => panic!("Expected Find command"),
        }
    }

    #[test]
    fn test_find_command_with_n() {
        let cli = Cli::try_parse_from(["llminus", "find", "5"]).unwrap();
        match cli.command {
            Commands::Find { n } => assert_eq!(n, 5),
            _ => panic!("Expected Find command"),
        }
    }

    #[test]
    fn test_resolve_command_parses() {
        let cli = Cli::try_parse_from(["llminus", "resolve", "my-llm"]).unwrap();
        match cli.command {
            Commands::Resolve { command, .. } => assert_eq!(command, "my-llm"),
            _ => panic!("Expected Resolve command"),
        }
    }

    #[test]
    fn test_resolve_command_with_args() {
        let cli = Cli::try_parse_from(["llminus", "resolve", "my-llm --model fancy"]).unwrap();
        match cli.command {
            Commands::Resolve { command, .. } => assert_eq!(command, "my-llm --model fancy"),
            _ => panic!("Expected Resolve command"),
        }
    }

    #[test]
    fn test_parse_merge_source() {
        // Standard branch merge
        assert_eq!(
            parse_merge_source("Merge branch 'feature-branch'"),
            Some("feature-branch".to_string())
        );

        // Tag merge
        assert_eq!(
            parse_merge_source("Merge tag 'v6.1'"),
            Some("v6.1".to_string())
        );

        // Remote tracking branch
        assert_eq!(
            parse_merge_source("Merge remote-tracking branch 'origin/main'"),
            Some("origin/main".to_string())
        );

        // Commit merge
        assert_eq!(
            parse_merge_source("Merge commit 'abc123def'"),
            Some("abc123def".to_string())
        );

        // Branch with "into" target
        assert_eq!(
            parse_merge_source("Merge branch 'feature' into master"),
            Some("feature".to_string())
        );

        // Non-merge line
        assert_eq!(parse_merge_source("Fix bug in foo"), None);
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

        let mut store = ResolutionStore { version: 3, resolutions: Vec::new(), processed_commits: Vec::new() };
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
        let original_dir = std::env::current_dir().unwrap();
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

        std::env::set_current_dir(original_dir).unwrap();
    }

    #[test]
    fn test_parse_conflict_markers() {
        let dir = TempDir::new().unwrap();
        let conflict_file = dir.path().join("conflict.c");
        let content = r#"int main() {
<<<<<<< HEAD
    printf("ours");
=======
    printf("theirs");
>>>>>>> feature
    return 0;
}
"#;
        fs::write(&conflict_file, content).unwrap();

        let conflicts = parse_conflict_file(conflict_file.to_str().unwrap()).unwrap();
        assert_eq!(conflicts.len(), 1);
        assert!(conflicts[0].ours_content.contains("ours"));
        assert!(conflicts[0].theirs_content.contains("theirs"));
        assert!(conflicts[0].base_content.is_none());
    }

    #[test]
    fn test_parse_conflict_markers_diff3() {
        let dir = TempDir::new().unwrap();
        let conflict_file = dir.path().join("conflict.c");
        // diff3 style with base content
        let content = r#"int main() {
<<<<<<< HEAD
    printf("ours");
||||||| base
    printf("base");
=======
    printf("theirs");
>>>>>>> feature
    return 0;
}
"#;
        fs::write(&conflict_file, content).unwrap();

        let conflicts = parse_conflict_file(conflict_file.to_str().unwrap()).unwrap();
        assert_eq!(conflicts.len(), 1);
        assert!(conflicts[0].ours_content.contains("ours"));
        assert!(conflicts[0].theirs_content.contains("theirs"));
        assert!(conflicts[0].base_content.as_ref().unwrap().contains("base"));
    }

    #[test]
    fn test_parse_multiple_conflicts() {
        let dir = TempDir::new().unwrap();
        let conflict_file = dir.path().join("conflict.c");
        let content = r#"<<<<<<< HEAD
first ours
=======
first theirs
>>>>>>> feature
middle
<<<<<<< HEAD
second ours
=======
second theirs
>>>>>>> feature
"#;
        fs::write(&conflict_file, content).unwrap();

        let conflicts = parse_conflict_file(conflict_file.to_str().unwrap()).unwrap();
        assert_eq!(conflicts.len(), 2);
        assert!(conflicts[0].ours_content.contains("first ours"));
        assert!(conflicts[1].ours_content.contains("second ours"));
    }

    #[test]
    fn test_pull_command_parses() {
        let cli = Cli::try_parse_from(["llminus", "pull", "test@kernel.org"]).unwrap();
        match cli.command {
            Commands::Pull { message_id, command, .. } => {
                assert_eq!(message_id, "test@kernel.org");
                assert_eq!(command, "llm"); // default
            }
            _ => panic!("Expected Pull command"),
        }
    }

    #[test]
    fn test_pull_command_with_custom_command() {
        let cli = Cli::try_parse_from([
            "llminus", "pull", "test@kernel.org", "-c", "my-llm --model fancy"
        ]).unwrap();
        match cli.command {
            Commands::Pull { message_id, command, .. } => {
                assert_eq!(message_id, "test@kernel.org");
                assert_eq!(command, "my-llm --model fancy");
            }
            _ => panic!("Expected Pull command"),
        }
    }

    #[test]
    fn test_parse_email_headers() {
        let raw = r#"From: Paul Walmsley <paul@kernel.org>
Subject: [GIT PULL] RISC-V updates for v6.19
Date: Thu, 11 Dec 2025 19:36:00 -0700
Message-ID: <test123@kernel.org>

This is the body of the email.
"#;
        let (from, subject, date, msg_id, body) = parse_email_headers(raw);
        assert_eq!(from, "Paul Walmsley <paul@kernel.org>");
        assert_eq!(subject, "[GIT PULL] RISC-V updates for v6.19");
        assert_eq!(date, "Thu, 11 Dec 2025 19:36:00 -0700");
        assert_eq!(msg_id, "<test123@kernel.org>");
        assert!(body.contains("This is the body"));
    }

    #[test]
    fn test_parse_email_headers_multiline() {
        let raw = r#"From: Paul Walmsley <paul@kernel.org>
Subject: [GIT PULL] RISC-V updates
 for v6.19 merge window
Date: Thu, 11 Dec 2025 19:36:00 -0700

Body here.
"#;
        let (_, subject, _, _, _) = parse_email_headers(raw);
        assert!(subject.contains("RISC-V updates"));
        assert!(subject.contains("for v6.19 merge window"));
    }

    #[test]
    fn test_extract_git_info() {
        let body = r#"Please pull this set of changes.

The following changes are available in the Git repository at:

  git://git.kernel.org/pub/scm/linux/kernel/git/riscv/linux tags/riscv-for-linus-6.19

for you to fetch changes up to abc123.
"#;
        let result = extract_git_info(body);
        assert!(result.is_some());
        let (url, git_ref) = result.unwrap();
        assert_eq!(url, "git://git.kernel.org/pub/scm/linux/kernel/git/riscv/linux");
        assert_eq!(git_ref, "tags/riscv-for-linus-6.19");
    }

    #[test]
    fn test_extract_git_info_https() {
        let body = r#"Available at:

  https://git.kernel.org/pub/scm/linux/kernel/git/foo/bar.git feature-branch

Thanks!
"#;
        let result = extract_git_info(body);
        assert!(result.is_some());
        let (url, git_ref) = result.unwrap();
        assert!(url.starts_with("https://git.kernel.org"));
        assert_eq!(git_ref, "feature-branch");
    }

    #[test]
    fn test_extract_git_info_none() {
        let body = "This email has no git URL in it.";
        let result = extract_git_info(body);
        assert!(result.is_none());
    }

    #[test]
    fn test_build_merge_commit_message() {
        let pull_req = PullRequest {
            message_id: "test123@kernel.org".to_string(),
            subject: "[GIT PULL] Important updates for v6.19".to_string(),
            from: "Maintainer <maintainer@kernel.org>".to_string(),
            date: "2025-12-11".to_string(),
            git_url: "git://git.kernel.org/pub/scm/foo".to_string(),
            git_ref: "tags/foo-for-v6.19".to_string(),
            body: String::new(),
        };

        let summary = "This is the maintainer's summary of changes.";
        let resolution = "Resolved by keeping both changes.";
        let msg = build_merge_commit_message(&pull_req, summary, resolution);
        assert!(msg.contains("Merge tags/foo-for-v6.19"));
        assert!(msg.contains("Important updates")); // subject without [GIT PULL]
        assert!(msg.contains("maintainer's summary"));
        assert!(msg.contains("conflict resolution"));
        assert!(msg.contains("keeping both changes"));
        assert!(msg.contains("https://lore.kernel.org/all/test123@kernel.org/"));
    }

    #[test]
    fn test_build_resolve_prompt_with_pull_request() {
        let conflicts = vec![ConflictFile {
            path: "test.c".to_string(),
            ours_content: "int ours;".to_string(),
            theirs_content: "int theirs;".to_string(),
            base_content: Some("int base;".to_string()),
        }];

        let pull_req = PullRequest {
            message_id: "test@kernel.org".to_string(),
            subject: "Test PR".to_string(),
            from: "Author <author@kernel.org>".to_string(),
            date: "2025-12-11".to_string(),
            git_url: "git://test".to_string(),
            git_ref: "tags/test".to_string(),
            body: "Test summary\n\nResolve by keeping both.".to_string(),
        };

        let merge_ctx = MergeContext {
            merge_source: Some("tags/test".to_string()),
            head_branch: Some("master".to_string()),
            merge_message: Some("Merge tags/test".to_string()),
        };

        let prompt = build_resolve_prompt(&conflicts, &[], &merge_ctx, Some(&pull_req));

        // Check that key sections are present
        assert!(prompt.contains("Pull Request Information"));
        assert!(prompt.contains("Test PR")); // subject
        assert!(prompt.contains("Test summary")); // body includes summary
        assert!(prompt.contains("Resolve by keeping both")); // body includes this
        assert!(prompt.contains("test.c")); // conflict file
        assert!(prompt.contains("int ours;")); // ours content
        assert!(prompt.contains("int theirs;")); // theirs content
        assert!(prompt.contains("Write a detailed explanation")); // pull request specific
    }

    #[test]
    fn test_build_resolve_prompt_without_pull_request() {
        let conflicts = vec![ConflictFile {
            path: "test.c".to_string(),
            ours_content: "int ours;".to_string(),
            theirs_content: "int theirs;".to_string(),
            base_content: None,
        }];

        let merge_ctx = MergeContext {
            merge_source: Some("feature-branch".to_string()),
            head_branch: Some("master".to_string()),
            merge_message: None,
        };

        let prompt = build_resolve_prompt(&conflicts, &[], &merge_ctx, None);

        // Check standard resolve sections
        assert!(prompt.contains("Linux Kernel Merge Conflict Resolution"));
        assert!(!prompt.contains("Pull Request Information"));
        assert!(prompt.contains("test.c"));
        assert!(prompt.contains("int ours;"));
        assert!(!prompt.contains("Write a detailed explanation")); // PR-specific, not in standard prompt
    }
}
