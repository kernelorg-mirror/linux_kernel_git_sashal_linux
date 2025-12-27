/* SPDX-License-Identifier: GPL-2.0-only OR BSD-3-Clause */
/******************************************************************************
 *
 * This file is provided under a dual license.  When you use or
 * distribute this software, you may choose to be licensed under
 * version 2 of the GNU General Public License ("GPLv2 License")
 * or BSD License.
 *
 * GPLv2 License
 *
 * Copyright(C) 2019 MediaTek Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See http://www.gnu.org/licenses/gpl-2.0.html for more details.
 *
 * BSD LICENSE
 *
 * Copyright(C) 2019 MediaTek Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *  * Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *****************************************************************************/

///////////////////////////////////////////////////////////////////////////////////////////////////
///
/// file    mdrv_mpool.c
/// @brief  Memory Pool Control Interface
/// @author MStar Semiconductor Inc.
///////////////////////////////////////////////////////////////////////////////////////////////////
//-------------------------------------------------------------------------------------------------
//  Include Files
//-------------------------------------------------------------------------------------------------
#include <generated/autoconf.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/delay.h>
#include <linux/kdev_t.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/ioport.h>
#include <linux/interrupt.h>
#include <linux/workqueue.h>
#include <linux/poll.h>
#include <linux/wait.h>
#include <linux/cdev.h>
#include <linux/time.h>  //added
#include <linux/timer.h> //added
#include <linux/device.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <linux/binfmts.h>
#include <asm/io.h>
#include <asm/types.h>
#include <asm/cacheflush.h>

#if defined(CONFIG_COMPAT)
#include <linux/compat.h>
#endif

#include "power.h"

#include "mdrv_mstypes.h"
#include "mdrv_pm.h"
#include "mhal_pm.h"
#include "mdrv_system.h"
#include "mdrv_gpio.h"

//--------------------------------------------------------------------------------------------------
//  Forward declaration
//--------------------------------------------------------------------------------------------------
#define MDRV_PM_DEBUG(fmt, args...)  printk(KERN_ERR "[%s][%d] " fmt, __func__, __LINE__, ## args)

#define RTPM_FW_PATH            "/config/RT_PM.bin"
#define RTPM_BUFF_SZ 128

#define INVALID_GPIO_NUM        (0xFF)
#define DEFAULT_BT_GPIO_NUM     (0x05)

/* MMAP lay out. */
#define PM_OFFSET_BT            (0x0070)
#define PM_OFFSET_USB           (0x0073)
#define PM_OFFSET_EWBS          (0x0075)
#define PM_OFFSET_BTW           (0x0078)
#define PM_OFFSET_VOICE         (0x007D)
#define PM_OFFSET_POWER_DOWN    (0x00A0)
#define PM_OFFSET_SAR0          (0x00C0)
#define PM_OFFSET_SAR1          (0x00E0)
#define PM_OFFSET_LED           (0x0140)
#define PM_OFFSET_IR_VER        (0x0150)
#define PM_OFFSET_IR_NORMAL     (0x0160) //data_size + data(4* irkey_number)
#define PM_OFFSET_IR_EXTEND     (0x0200) //data_size + data(7* irkey_number)

#define PM_SUPPORT_SAR_KEYS_MAX     5

//--------------------------------------------------------------------------------------------------
//  Local variable
//--------------------------------------------------------------------------------------------------

//-------------------------------------------------------------------------------------------------
//  Golbal variable
//-------------------------------------------------------------------------------------------------
unsigned long long gPM_DramAddr = 0x10000;
unsigned long gPM_DramSize = DRAM_MMAP_SZ;
unsigned long long gPM_DataAddr = 0;
unsigned long gPM_DataSize = 0x1000;
static char pm_path[CORENAME_MAX_SIZE]={0};
static char pm_path_exist = 0;
static char gPM_Buf[0x10000];
#ifdef CONFIG_MP_AMAZON_WOL
static atomic_t PM_WOL_EN = ATOMIC_INIT(0);
#endif

static unsigned int     gRTPM_Enable = 0;
static unsigned int     gRTPM_Live = 1;
static unsigned long long gRTPM_Addr = 0;
static char             gRTPM_Path[RTPM_BUFF_SZ] = {0};

static u8 gUSBCfg = PM_SOURCE_DISABLE;
static PM_Cfg_t gstPMCfg;
static PM_WoBT_WakeCfg      gstWoBTCfg = {0};
static u8 gstWoBTW = PM_SOURCE_DISABLE;
static PM_WoEWBS_WakeCfg    gstWoEWBSCfg = {0};
static PM_WoV_WakeCfg       gstWoVCfg = {0};
static SAR_RegCfg gstSARCfg;
static SAR_RegCfg gstSARCfg1;
static PM_IrInfoCfg_t gstIrInfoCfg;
static u8 u8LedPara[10];
static u8 u8PowerOffLed = 0xFF;
static u8 u8IRVersion = IR_NO_INI_VERSION_NUM;
static u8 u8IRCfg[32] = {0};
//-------------------------------------------------------------------------------------------------
//  Data structure
//-------------------------------------------------------------------------------------------------

//-------------------------------------------------------------------------------------------------
//  Local function
//-------------------------------------------------------------------------------------------------
static unsigned long long _MDrv_PM_Ba2Pa(unsigned long long ba)
{
    unsigned long long pa = 0;

    if ((ba > ARM_MIU0_BUS_BASE) && (ba <= ARM_MIU1_BUS_BASE))
        pa = ba - ARM_MIU0_BUS_BASE + ARM_MIU0_BASE_ADDR;
    else if ((ba > ARM_MIU1_BUS_BASE) && (ba <= ARM_MIU2_BUS_BASE))
        pa = ba - ARM_MIU1_BUS_BASE + ARM_MIU1_BASE_ADDR;
    else
        MDRV_PM_DEBUG("ba=0x%llX, pa=0x%llX.\n", ba, pa);

    return pa;
}

static unsigned long long _MDrv_PM_Pa2Ba(unsigned long long pa)
{
    unsigned long long ba = 0;

    if ((pa > ARM_MIU0_BASE_ADDR) && (pa <= ARM_MIU1_BASE_ADDR))
        ba = pa + ARM_MIU0_BUS_BASE - ARM_MIU0_BASE_ADDR;
    else if ((pa > ARM_MIU1_BASE_ADDR) && (pa <= ARM_MIU2_BASE_ADDR))
        ba = pa + ARM_MIU1_BUS_BASE - ARM_MIU1_BASE_ADDR;
    else
        MDRV_PM_DEBUG("pa=0x%llX, ba=0x%llX.\n", pa, ba);

    return ba;
}

static PM_Result _MDrv_PM_Get_RTPM_Path(char *path)
{
    int ret = E_PM_OK;
    struct file *fp = NULL;
    mm_segment_t fs;
    loff_t pos = 0;
    int blk = 1;
    char buff[RTPM_BUFF_SZ] = {0};

    /* Find /config/RT_PM.bin. */
    fp = filp_open(RTPM_FW_PATH, O_RDONLY, 0);
    if (!IS_ERR(fp))
    {
        strncpy(path, RTPM_FW_PATH, RTPM_BUFF_SZ);
        filp_close(fp, NULL);
        return E_PM_OK;
    }

    /* Find /dev/block/platform/mstar_mci.0/by-name/RTPM exist. */
    snprintf(buff, RTPM_BUFF_SZ, "/dev/block/platform/mstar_mci.0/by-name/RTPM");
    fp = filp_open(buff, O_RDONLY, 0);
    if ((!IS_ERR(fp)) || (PTR_ERR(fp) == -EACCES))
    {
        strncpy(path, buff, RTPM_BUFF_SZ);
        if (!IS_ERR(fp))
            filp_close(fp, NULL);
        return E_PM_OK;
    }

    /* Store fs. */
    fs = get_fs();
    set_fs(KERNEL_DS);

    /* Find /dev/mmcblk0p#. */
    do
    {
        memset(buff, '\0', RTPM_BUFF_SZ);
        snprintf(buff, RTPM_BUFF_SZ, "/sys/block/mmcblk0/mmcblk0p%d/uevent", blk);
        fp = filp_open(buff, O_RDONLY, 0);
        if (IS_ERR(fp))
        {
            MDRV_PM_DEBUG("RTPM path not found.\n");
            ret = E_PM_FAIL;
            goto _MDrv_PM_Get_RTPM_Path_End;
        }
        memset(buff, '\0', RTPM_BUFF_SZ);
        vfs_read(fp, buff, RTPM_BUFF_SZ, &pos);
        filp_close(fp, NULL);

        /* Check found. */
        if (strnstr(buff, "PARTNAME=RTPM", RTPM_BUFF_SZ))
        {
            memset(buff, '\0', RTPM_BUFF_SZ);
            snprintf(buff, RTPM_BUFF_SZ, "/dev/mmcblk0p%d", blk);
            fp = filp_open(buff, O_RDONLY, 0);
            if (!IS_ERR(fp))
            {
                snprintf(path, RTPM_BUFF_SZ, "/dev/mmcblk0p%d", blk);
                filp_close(fp, NULL);
            }
            else
            {
                snprintf(path, RTPM_BUFF_SZ, "/dev/mmcblk%d", blk);
            }
            break;
        }
        else
        {
            pos = 0;
            blk++;
        }
    } while (1);

_MDrv_PM_Get_RTPM_Path_End:
    /* Restore fs. */
    set_fs(fs);

    return ret;
}

static PM_Result _MDrv_PM_Copy_RTPM_Bin(unsigned long long dst_addr, char *src_path)
{
    struct file *fp = NULL;
    mm_segment_t fs;
    loff_t pos = 0;
    phys_addr_t *va = 0;

    /* Check data init. */
    if ((strlen(src_path) == 0) || (dst_addr == 0))
    {
        MDRV_PM_DEBUG("RTPM data error: path=%s, addr=0x%llX.\n", src_path, dst_addr);
        return E_PM_FAIL;
    }

    /*
     * Prepare flow:
     * 1. open fd.
     * 2. ioremap_wc address.
     * 3. store fs.
     */
    fp = filp_open(src_path, O_RDONLY, 0);
    if (IS_ERR(fp))
    {
        MDRV_PM_DEBUG("filp_open() fail.\n");
        return E_PM_FAIL;
    }
    va = ioremap_wc(dst_addr, DRAM_MMAP_SZ);
    if (va == NULL)
    {
        MDRV_PM_DEBUG("ioremap_wc() fail.\n");
        return E_PM_FAIL;
    }
    fs = get_fs();
    set_fs(KERNEL_DS);

    /* Copy form RTPM partition to DRAM address. */
    vfs_read(fp, (char *)va, DRAM_MMAP_SZ, &pos);

    /*
     * Complete to do:
     * 1. restore fs.
     * 2. un-ioremap_wc address.
     * 3. close fd.
     */
    set_fs(fs);
    iounmap(va);
    filp_close(fp, NULL);

    return E_PM_OK;
}

static PM_Result _MDrv_PM_Set_Data(u16 u16Key, void *pSrc, unsigned long long ulDest, u8 u8Size)
{
    PM_Result eRet = E_PM_OK;
    phys_addr_t *pVa = NULL;

    /*
     * [byte-0]      : Command index for check.
     * [byte-1 ~ ...]: Original info.
     */
    switch (u16Key)
    {
        case PM_KEY_BT:
            pVa = ioremap_wc(_MDrv_PM_Pa2Ba(ulDest + PM_OFFSET_BT), u8Size + 1);
            break;

        case PM_KEY_BTW:
            pVa = ioremap_wc(_MDrv_PM_Pa2Ba(ulDest + PM_OFFSET_BTW), u8Size + 1);
            break;

        case PM_KEY_EWBS:
            pVa = ioremap_wc(_MDrv_PM_Pa2Ba(ulDest + PM_OFFSET_EWBS), u8Size + 1);
            break;

        case PM_KEY_VOICE:
            pVa = ioremap_wc(_MDrv_PM_Pa2Ba(ulDest + PM_OFFSET_VOICE), u8Size + 1);
            break;

        case PM_KEY_USB:
            pVa = ioremap_wc(_MDrv_PM_Pa2Ba(ulDest + PM_OFFSET_USB), u8Size + 1);
            break;

        default:
            MDRV_PM_DEBUG("u16Key=0x%X not support.\n", u16Key);
            eRet = E_PM_FAIL;
            break;
    }

    /* Check mapping result. */
    if (eRet == E_PM_OK)
    {
        if (pVa == NULL)
        {
            MDRV_PM_DEBUG("ioremap_wc() fail.\n");
            eRet = E_PM_FAIL;
        }
        else
        {
            *((u8 *)pVa + 0) = (u8)u16Key;
            memcpy((void *)((u8 *)pVa + 1), pSrc, u8Size);
            iounmap(pVa);
        }
    }

    return eRet;
}

//-------------------------------------------------------------------------------------------------
//  Golbal function
//-------------------------------------------------------------------------------------------------
ssize_t MDrv_PM_Read_Key(u16 u16Key, const char *buf)
{
    ssize_t tSize = 0;
    void *pPtr = NULL;
    u32 u32Idx = 0;

    switch (u16Key)
    {
        case PM_KEY_BT:
            tSize = sizeof(PM_WoBT_WakeCfg);
            pPtr = &gstWoBTCfg;
            break;

        case PM_KEY_BTW:
            tSize = sizeof(gstWoBTW);
            pPtr = &gstWoBTW;
            break;

        case PM_KEY_EWBS:
            tSize = sizeof(PM_WoEWBS_WakeCfg);
            pPtr = &gstWoEWBSCfg;
            break;

        case PM_KEY_VOICE:
            tSize = sizeof(PM_WoV_WakeCfg);
            pPtr = &gstWoVCfg;
            break;

        case PM_KEY_USB:
            tSize = sizeof(gUSBCfg);
            pPtr = &gUSBCfg;
            break;

        case PM_KEY_POWER_DOWN:
            tSize = sizeof(PM_PowerDownCfg_t);
            pPtr = &gstPMCfg.stPMPowerDownCfg;
            break;

        case PM_KEY_SAR:
            tSize = sizeof(SAR_RegCfg);
            pPtr = &gstSARCfg;
            break;

        case PM_KEY_LED:
            tSize = sizeof(u8LedPara);
            pPtr = &u8LedPara;
            break;
        default:
            tSize = sizeof(PM_WakeCfg_t);
            pPtr = &gstPMCfg.stPMWakeCfg;
            break;
    }

    memcpy((void *)buf, (const void *)pPtr, tSize);

MDrv_PM_Read_Key_End:
    return tSize;
}
EXPORT_SYMBOL(MDrv_PM_Read_Key);

ssize_t MDrv_PM_Write_Key(u16 u16Key, const char *buf, size_t size)
{
    ssize_t tSize = 0;
    void *pPtr = NULL;

    switch (u16Key)
    {
        case PM_KEY_BT:
            tSize = sizeof(PM_WoBT_WakeCfg);
            pPtr = &gstWoBTCfg;
            break;

        case PM_KEY_BTW:
            tSize = sizeof(gstWoBTW);
            pPtr = &gstWoBTW;
            break;

        case PM_KEY_EWBS:
            tSize = sizeof(PM_WoEWBS_WakeCfg);
            pPtr = &gstWoEWBSCfg;
            break;

        case PM_KEY_VOICE:
            tSize = sizeof(PM_WoV_WakeCfg);
            pPtr = &gstWoVCfg;
            break;

        case PM_KEY_USB:
            tSize = sizeof(gUSBCfg);
            pPtr = &gUSBCfg;
            break;

        case PM_KEY_POWER_DOWN:
            tSize = sizeof(PM_PowerDownCfg_t);
            pPtr = &gstPMCfg.stPMPowerDownCfg;
            break;

        case PM_KEY_SAR:
            tSize = sizeof(SAR_RegCfg);
            pPtr = &gstSARCfg;
            break;

        case PM_KEY_LED:
            tSize = sizeof(u8LedPara);
            pPtr = &u8LedPara;
            break;

        case PM_KEY_IR:
            tSize = sizeof(PM_IrInfoCfg_t);
            pPtr = &gstIrInfoCfg;
            break;

        default:
            tSize = sizeof(PM_WakeCfg_t);
            pPtr = &gstPMCfg.stPMWakeCfg;
            break;
    }

    /* Check data size align. */
    if (size != tSize)
        MDRV_PM_DEBUG("Data(0x%X) un-align: input_size=0x%X, internal_size=0x%X\n", u16Key, size, tSize);
    else
        memcpy((void *)pPtr, (const void *)buf, tSize);

    return tSize;
}
EXPORT_SYMBOL(MDrv_PM_Write_Key);

u8 MDrv_PM_GetPowerOnKey(void)
{
    return MHal_PM_GetPowerOnKey();
}

void MDrv_PM_CleanPowerOnKey(void)
{
    MHal_PM_CleanPowerOnKey();
}

void MDrv_PM_Set_PowerOffLed(u8 u8LedPad)
{
    MDRV_PM_DEBUG("LedPadNum = %d\n",u8LedPad);
    u8PowerOffLed = u8LedPad;
    return;
}

u8 MDrv_PM_Get_PowerOffLed(void)
{
    return u8PowerOffLed;
}

ssize_t MDrv_PM_Set_IRCfg(const u8 *buf, size_t size)
{
    u8IRVersion = IR_INI_VERSION_NUM;
    memcpy((void *)u8IRCfg, buf, sizeof(u8IRCfg));

    return sizeof(u8IRCfg);
}

EXPORT_SYMBOL(MDrv_PM_Set_IRCfg);

static u8 MDrv_PM_Get_IRVersion(void)
{
    return gstIrInfoCfg.u8IrVersion;
}

static void MDrv_PM_Copy_IRCfg(PM_Cfg_t* pstPMCfg)
{
#if 0 // for debug used
    u8 i = 0;
#endif
    if (MDrv_PM_Get_IRVersion() == IR_INI_VERSION_NUM)
    {
        MDRV_PM_DEBUG("IRVersion = 0x20,copy u8IRCfg to u8PmWakeIR!\n");
        memcpy((void*)&(pstPMCfg->stPMWakeCfg.u8PmWakeIR[PM_SUPPORT_SAR_KEYS_MAX]), \
        (void*)&(u8IRCfg[0]), (sizeof(u8IRCfg) -PM_SUPPORT_SAR_KEYS_MAX));
#if 0 // for debug used
        for(i=0;i<MAX_BUF_WAKE_IR;i++)
        {
            printk( "[Kernel_pm]   IR List  = 0x%x\n", pstPMCfg->stPMWakeCfg.u8PmWakeIR[i]);
        }
#endif
    }
    else
    {
        MDRV_PM_DEBUG("IRVersion = 0x10,use origin IRCfg!\n");
    }
}

void MDrv_PM_Show_PM_Info(void)
{
    u8 i = 0;

    // stPMWakeCfg
    printk("======== stPMWakeCfg start ========\n");
    printk("EnableIR     = %x\n", gstPMCfg.stPMWakeCfg.bPmWakeEnableIR);
    printk("EnableSAR    = %x\n", gstPMCfg.stPMWakeCfg.bPmWakeEnableSAR);
    printk("EnableGPIO0  = %x\n", gstPMCfg.stPMWakeCfg.bPmWakeEnableGPIO0);
    printk("EnableGPIO1  = %x\n", gstPMCfg.stPMWakeCfg.bPmWakeEnableGPIO1);
    printk("EnableUART1  = %x\n", gstPMCfg.stPMWakeCfg.bPmWakeEnableUART1);
    printk("EnableSYNC   = %x\n", gstPMCfg.stPMWakeCfg.bPmWakeEnableSYNC);
    printk("EnableRTC0   = %x\n", gstPMCfg.stPMWakeCfg.bPmWakeEnableRTC0);
    printk("EnableRTC1   = %x\n", gstPMCfg.stPMWakeCfg.bPmWakeEnableRTC1);
    printk("EnableDVI0   = %x\n", gstPMCfg.stPMWakeCfg.bPmWakeEnableDVI0);
    printk("EnableDVI2   = %x\n", gstPMCfg.stPMWakeCfg.bPmWakeEnableDVI2);
    printk("EnableCEC    = %x\n", gstPMCfg.stPMWakeCfg.bPmWakeEnableCEC);
    printk("EnableAVLINK = %x\n", gstPMCfg.stPMWakeCfg.bPmWakeEnableAVLINK);
    printk("EnableMHL    = %x\n", gstPMCfg.stPMWakeCfg.bPmWakeEnableMHL);
    printk("EnableWOL    = %x\n", gstPMCfg.stPMWakeCfg.bPmWakeEnableWOL);
    printk("EnableCM4    = %x\n", gstPMCfg.stPMWakeCfg.bPmWakeEnableCM4);

    printk("EnableUSB    = %tx\n", (size_t)gUSBCfg);

    printk("PmStrMode = %x\n", gstPMCfg.stPMWakeCfg.u8PmStrMode);

    for(i = 0; i<32; i++)
        printk("IR List =  0x%x\n", gstPMCfg.stPMWakeCfg.u8PmWakeIR[i]);

    for(i = 0; i<16; i++)
        printk("IR List2 =  0x%x\n", gstPMCfg.stPMWakeCfg.u8PmWakeIR2[i]);

    for(i = 0; i<MAX_BUF_WAKE_MAC_ADDRESS; i++)
        printk("MAC = 0x%x\n", gstPMCfg.stPMWakeCfg.u8PmWakeMACAddress[i]);
    printk("======== stPMWakeCfg end   ========\n");

    // stPMPowerDownCfg
    printk("======== stPMPowerDownCfg start ======== \n");
    printk("PowerDownMode = 0x%x\n", gstPMCfg.stPMPowerDownCfg.u8PowerDownMode);
    printk("WakeAddress = 0x%x\n", gstPMCfg.stPMPowerDownCfg.u8WakeAddress);
    printk("======== stPMPowerDownCfg end   ======== \n");

    //SAR_RegCfg1
    printk("======== MDrv_SAR_CfgChInfo start ========= \n");
    printk("u8SARChID=0x%02X\n", gstSARCfg.u8SARChID);
    printk("tSARChBnd.u8UpBnd=0x%02x\n", gstSARCfg.tSARChBnd.u8UpBnd);
    printk("tSARChBnd.u8LoBnd=0x%02x\n", gstSARCfg.tSARChBnd.u8LoBnd);
    printk("u8KeyLevelNum=0x%02x\n", gstSARCfg.u8KeyLevelNum);
    for(i=0; i < gstSARCfg.u8KeyLevelNum; i++)
        printk("u8KeyThreshold[%d]=0x%02x\n", i, gstSARCfg.u8KeyThreshold[i]);
    for(i=0; i < gstSARCfg.u8KeyLevelNum; i++)
        printk("u8KeyCode[%d]=0x%02x\n", i, gstSARCfg.u8KeyCode[i]);

    printk("======== MDrv_SAR_CfgChInfo end   ========= \n");

    //LED_RegCfg
    printk("======== MDrv_LED_CfgChInfo start ========= \n");
    for(i=0; i < 10; i++)
        printk("u8LedPara[%d]=0x%02x\n",i,u8LedPara[i]);
    printk("======== MDrv_LED_CfgChInfo end   ========= \n");
}

void MDrv_PM_ShowIrWakeupKeyInfo(void)
{
    u8 i = 0;
    printk("========= IR WakeUp Key Info  =========\n");
    printk("IR version = 0x%x \n",gstIrInfoCfg.u8IrVersion);
    printk("IR Normal Key Number = %d \n",gstIrInfoCfg.u8NormalKeyNumber);
    for(i = 0; i<= gstIrInfoCfg.u8NormalKeyNumber; i++)
    {
        printk("au8IrNormalKey[%d] = 0x%x\n",i,gstIrInfoCfg.au8IrNormalKey[i]);
    }
    printk("IR Extend Key Number = %d \n",gstIrInfoCfg.u8ExtendKeyNumber);
    for(i = 0; i<= gstIrInfoCfg.u8ExtendKeyNumber; i++)
    {
        printk("au8IrExtendKey[%d] = 0x%x\n",i,gstIrInfoCfg.au8IrExtendKey[i]);
    }
}

#ifdef CONFIG_MP_AMAZON_WOL
void MDrv_PM_Show_PM_WOL_EN(void)
{
	printk("Current Parameter of WOL_EN=%d \n", atomic_read(&PM_WOL_EN));
}

void MDrv_PM_SetPM_WOL_EN(const char *buf)
{
	unsigned int WOL_EN = 0;
	int readCount = 0;

	readCount = sscanf(buf, "%d", &WOL_EN);
	if (readCount != 1) {
		printk("ERROR cannot read WOL_EN from [%s] \n", buf);
		return;
	}
	if (WOL_EN > 0x01) {
		printk("ERROR Parameter WOL_EN=%d \n", WOL_EN);
		return;
	}

	printk("Set Parameter WOL_EN=%d success\n", WOL_EN);
	atomic_set(&PM_WOL_EN, WOL_EN);
}
#endif

PM_Result MDrv_PM_SetSRAMOffsetForMCU(void)
{
    PM_Result result;
    u8 u8LedPad = 0;

    result = MHal_PM_CopyBin2Sram(gPM_DramAddr);
    if (result != E_PM_OK)
    {
        return result;
    }

    MHal_PM_SetDram2Register(gPM_DataAddr);

    #if(CONFIG_MSTAR_GPIO)
    u8LedPad = MDrv_PM_Get_PowerOffLed();
    MDRV_PM_DEBUG("Get LedPadNum = %d\n",u8LedPad);
    if(u8LedPad != 0xFF)
    {
        MDRV_PM_DEBUG("======= set red led on ========\n");
        // set red gpio on
        MDrv_GPIO_Set_Low(u8LedPad);
    }
    #endif

    result = MHal_PM_SetSRAMOffsetForMCU();

    return result;
}

PM_Result MDrv_PM_SetSRAMOffsetForMCU_DC(void)
{
    PM_Result result;
    u8 u8LedPad = 0;

    MDRV_PM_DEBUG("start MDrv_PM_SetSRAMOffsetForMCU_DC \n");
    result = MHal_PM_CopyBin2Sram(gPM_DramAddr);
    if (result != E_PM_OK)
    {
        return result;
    }

    MHal_PM_SetDram2Register(gPM_DataAddr);

    #if(CONFIG_MSTAR_GPIO)
    u8LedPad = MDrv_PM_Get_PowerOffLed();
    MDRV_PM_DEBUG("Get LedPadNum = %d\n",u8LedPad);
    if(u8LedPad != 0xFF)
    {
        MDRV_PM_DEBUG("======= set red led on ========\n");
        // set red gpio on
        MDrv_GPIO_Set_Low(u8LedPad);
    }
    #endif

    result = MHal_PM_SetSRAMOffsetForMCU_DC();
    MDRV_PM_DEBUG("finish MDrv_PM_SetSRAMOffsetForMCU_DC \n");

    return result;
}

PM_Result MDrv_PM_CopyBin2Sram(void)
{
    phys_addr_t *remap_addr = NULL;


    MHal_PM_RunTimePM_Disable_PassWord();

    MDRV_PM_DEBUG("start MDrv_PM_CopyBin2Sram \n");

    remap_addr = (phys_addr_t *)ioremap_wc(gPM_DramAddr + ARM_MIU0_BUS_BASE, gPM_DramSize);
    if (remap_addr == NULL)
    {
        MDRV_PM_DEBUG("ioremap_wc failed\n");
        return E_PM_FAIL;
    }

    memcpy(remap_addr, gPM_Buf, gPM_DramSize);

    iounmap(remap_addr);

    return E_PM_OK;
}

PM_Result MDrv_PM_CopyBin2Dram(void)
{
    struct file *fp = NULL;
    mm_segment_t fs;
    loff_t pos;

    MDRV_PM_DEBUG("start MDrv_PM_CopyBin2Dram \n");

    if (pm_path_exist) {
        fp = filp_open(pm_path, O_RDONLY, 0);
        if (IS_ERR(fp)) {
            MDRV_PM_DEBUG("Only for Fusion Project: power off and recovery!!!\n");
            fp = filp_open("/mnt/vendor/tvservice/glibc/bin/PM.bin", O_RDONLY, 0);
        }
    }
    else
        fp = filp_open("/config/PM.bin", O_RDONLY, 0);

    if (IS_ERR(fp)){
        MDRV_PM_DEBUG("filp_open failed\n");
        return E_PM_FAIL;
    }
    fs = get_fs();
    set_fs(KERNEL_DS);
    pos = 0;
    memset(gPM_Buf, 0, gPM_DramSize);
    vfs_read(fp, gPM_Buf, gPM_DramSize, &pos);

    filp_close(fp, NULL);
    set_fs(fs);

    return E_PM_OK;
}

PM_Result MDrv_PM_Suspend(PM_STATE state)
{
    PM_Result result = E_PM_OK;
    PM_Cfg_t stPMCfg;

    switch (state)
    {
        /* System can read mmc partition, but can be wake up (can't disable). */
        case E_PM_STATE_STORE_INFO:
            /* Get RTPM bin path. */
            if (gRTPM_Enable == 1)
            {
                /* Check path exist. */
                if (strlen(gRTPM_Path) == 0)
                {
                    result = _MDrv_PM_Get_RTPM_Path(gRTPM_Path);
                }
            }

            /* Copy PM bin from mmc partition to DRAM. */
            if (!is_mstar_str())
            {
                result = MDrv_PM_CopyBin2Dram();
            }
            break;

        /* System can't be wake up, but also can't read mmc partition. */
        case E_PM_STATE_SUSPEND_PREPARE:
            /* Copy PM bin from DRAM to SRAM (copy bin after disable). */
            if (!is_mstar_str())
            {
                MDrv_PM_CopyBin2Sram();
            }
            gRTPM_Live = 0;
            break;

        /* System IP can't work. */
        case E_PM_STATE_DC_OFF:
            memset(&stPMCfg, 0, sizeof(stPMCfg));
            MDrv_PM_GetCfg(&stPMCfg);
#ifdef CONFIG_MP_AMAZON_WOL
            /* This WOL_EN can be set through device node */
            stPMCfg.stPMWakeCfg.bPmWakeEnableWOL = (u8) atomic_read(&PM_WOL_EN);
#endif
            stPMCfg.stPMWakeCfg.u8PmStrMode = PM_DC_MODE;
            MDrv_PM_SetCfg(&stPMCfg);
        case E_PM_STATE_STR_OFF:
            MHal_PM_Set_Reg_For_Led();    //turn off led light
            memset(&stPMCfg, 0, sizeof(stPMCfg));
            MDrv_PM_GetCfg(&stPMCfg);
            stPMCfg.stPMWakeCfg.bPmWakeEnableCM4 = gstPMCfg.stPMWakeCfg.bPmWakeEnableCM4;
            MDrv_PM_Copy_IRCfg(&stPMCfg);
            MDrv_PM_SetCfg(&stPMCfg);
            _MDrv_PM_Set_Data(PM_KEY_BT,    (void *)&gstWoBTCfg,    gPM_DataAddr, sizeof(PM_WoBT_WakeCfg));
            _MDrv_PM_Set_Data(PM_KEY_BTW,   (void *)&gstWoBTW,      gPM_DataAddr, sizeof(gstWoBTW));
            _MDrv_PM_Set_Data(PM_KEY_EWBS,  (void *)&gstWoEWBSCfg,  gPM_DataAddr, sizeof(PM_WoEWBS_WakeCfg));
            _MDrv_PM_Set_Data(PM_KEY_VOICE, (void *)&gstWoVCfg,     gPM_DataAddr, sizeof(PM_WoV_WakeCfg));
            _MDrv_PM_Set_Data(PM_KEY_USB,   (void *)&gUSBCfg,       gPM_DataAddr, sizeof(gUSBCfg));
            MDrv_PM_SetSRAMOffsetForMCU();
            break;

        default:
            result = E_PM_FAIL;
            break;
    }

    return result;
}

extern void add_timestamp(char *buffer);

PM_Result MDrv_PM_Resume(PM_STATE state)
{
    PM_Result result = E_PM_OK;
#if (SUPPORT_LDM_DELAY==1)
    u32 cnt = 0;
#endif

    MHal_PM_Set_Reg_For_DC_On(MDrv_PM_GetWakeupSource());
    switch (state)
    {
        case E_PM_STATE_STR_ON:
            /* Copy RTPM bin and Enable RTPM. */
            if (gRTPM_Enable == 1)
            {
                add_timestamp("[DRV][PM]PmResume__START");
                /* Check data. */
                if ((strlen(gRTPM_Path) == 0) || (gRTPM_Addr == 0))
                {
                    MDRV_PM_DEBUG("Data error: path=%s addr=0x%tX.\n", gRTPM_Path, (size_t)gRTPM_Addr);
                    result = E_PM_FAIL;
                    break;
                }

                /* Check PM live. */
                if (gRTPM_Live == 0)
                {
#if (SUPPORT_LDM_DELAY==1)
                    add_timestamp("[DRV][PM]PmWaitBacklightTiming__START");
                    while(MHal_PM_GetBacklightCheck() != 0x01)
                    {
                        if (cnt%15 ==0)
                            printk("PM51 check backlight delay cnt = %d, check = 0x%X\n", cnt, MHal_PM_GetBacklightCheck());
                        if (cnt > 250)
                        {
                            printk("PM51 check backlight delay timeout with dummy = 0x%X, force load RTPM\n", MHal_PM_GetBacklightCheck());
                            break;
                        }
                        mdelay(10); // check blocking dummy every 10 ms
                        cnt++;
                    }
                    MHal_PM_SetBacklightCheck(0x02);
                    add_timestamp("[DRV][PM]PmWaitBacklightTiming__END");
#endif
                    add_timestamp("[DRV][PM]PmLoadRt51__START");
                    MHal_PM_Disable_8051();
                    result = _MDrv_PM_Copy_RTPM_Bin(gRTPM_Addr, gRTPM_Path);
                    MHal_PM_SetDRAMOffsetForMCU(_MDrv_PM_Ba2Pa(gRTPM_Addr));
                    gRTPM_Live = 1;
                    add_timestamp("[DRV][PM]PmLoadRt51__END");
                }
                add_timestamp("[DRV][PM]PmResume__END");
            }
            break;
        default:
            result = E_PM_FAIL;
            break;
    }

    return result;
}

PM_Result MDrv_PM_SetPMCfg(u8 u8PmStrMode)
{
    phys_addr_t *remap_addr = NULL;
    remap_addr = (phys_addr_t *)ioremap_wc(gPM_DataAddr + ARM_MIU0_BUS_BASE, gPM_DataSize);
    if (remap_addr == NULL)
    {
        MDRV_PM_DEBUG("ioremap_wc failed\n");
        return E_PM_FAIL;
    }
    printk("gPM_DramAddr = 0x%x, gPM_DramSize = 0x%x\n",gPM_DramAddr,gPM_DramSize);
    printk("gPM_DataAddr = 0x%x, gPM_DataSize = 0x%x\n",gPM_DataAddr,gPM_DataSize);
    MDrv_PM_Copy_IRCfg(&gstPMCfg);
    gstPMCfg.stPMWakeCfg.u8PmStrMode = u8PmStrMode;
    memcpy((void*)remap_addr, (void*)&(gstPMCfg.stPMWakeCfg), sizeof(PM_WakeCfg_t));
    memcpy((void*)remap_addr + PM_OFFSET_POWER_DOWN, (void*)&(gstPMCfg.stPMPowerDownCfg), sizeof(PM_PowerDownCfg_t));
    memcpy((void*)remap_addr + PM_OFFSET_SAR0, (void*)&(gstSARCfg), sizeof(SAR_RegCfg));
    memcpy((void*)remap_addr + PM_OFFSET_SAR1, (void*)&(gstSARCfg1), sizeof(SAR_RegCfg));
    memcpy((void*)remap_addr + PM_OFFSET_LED, (void*)u8LedPara, sizeof(u8LedPara));
    memcpy((void*)remap_addr + PM_OFFSET_IR_VER, (void*)&gstIrInfoCfg.u8IrVersion, sizeof(u8));
    memcpy((void*)remap_addr + PM_OFFSET_IR_NORMAL, (void*)&gstIrInfoCfg.u8NormalKeyNumber, IR_POWER_KEY_NORMAL_SIZE_MAX+1);
    memcpy((void*)remap_addr + PM_OFFSET_IR_EXTEND, (void*)&gstIrInfoCfg.u8ExtendKeyNumber, IR_POWER_KEY_EXTEND_SIZE_MAX+1);

    iounmap(remap_addr);
    _MDrv_PM_Set_Data(PM_KEY_BT,    (void *)&gstWoBTCfg,    gPM_DataAddr, sizeof(PM_WoBT_WakeCfg));
    _MDrv_PM_Set_Data(PM_KEY_BTW,   (void *)&gstWoBTW,      gPM_DataAddr, sizeof(gstWoBTW));
    _MDrv_PM_Set_Data(PM_KEY_EWBS,  (void *)&gstWoEWBSCfg,  gPM_DataAddr, sizeof(PM_WoEWBS_WakeCfg));
    _MDrv_PM_Set_Data(PM_KEY_VOICE, (void *)&gstWoVCfg,     gPM_DataAddr, sizeof(PM_WoV_WakeCfg));
    _MDrv_PM_Set_Data(PM_KEY_USB,   (void *)&gUSBCfg,       gPM_DataAddr, sizeof(gUSBCfg));
    return E_PM_OK;
}

PM_Result MDrv_PM_PMCfg_Init(void)
{
    u8 idx = 0;

    MDRV_PM_DEBUG("start MDrv_PM_PMCfg_Init \n");


    memset(&gstPMCfg, 0, sizeof(gstPMCfg));
    gstPMCfg.stPMWakeCfg.u8PmWakeEnableWOWLAN = INVALID_GPIO_NUM;
    memset(&gstWoBTCfg, 0, sizeof(gstWoBTCfg));
    gstWoBTCfg.u8GpioNum = DEFAULT_BT_GPIO_NUM;
    memset(&gstWoEWBSCfg, 0, sizeof(gstWoEWBSCfg));
    gstWoEWBSCfg.u8GpioNum = INVALID_GPIO_NUM;
    memset(&gstSARCfg, 0, sizeof(gstSARCfg));
    memset(&gstSARCfg1, 0, sizeof(gstSARCfg1));

    gstWoBTW = PM_SOURCE_DISABLE;
    gUSBCfg = PM_SOURCE_DISABLE;

    //WakeUpCfg
    gstPMCfg.stPMWakeCfg.bPmWakeEnableIR = 1;
    gstPMCfg.stPMWakeCfg.bPmWakeEnableSAR = 1;
    gstPMCfg.stPMWakeCfg.bPmWakeEnableRTC0 = 1;
    gstPMCfg.stPMWakeCfg.bPmWakeEnableRTC1 = 1;
    gstPMCfg.stPMWakeCfg.bPmWakeEnableCEC = 1;
    gstPMCfg.stPMWakeCfg.bPmWakeEnableGPIO0 = 1;

    for(idx=0; idx<MAX_BUF_WAKE_IR; idx++)
    {
        gstPMCfg.stPMWakeCfg.u8PmWakeIR[idx] = 0xff;
    }
    gstPMCfg.stPMWakeCfg.u8PmWakeIR[0] = 0x46;

    for(idx=0; idx<MAX_BUF_WAKE_IR2; idx++)
    {
        gstPMCfg.stPMWakeCfg.u8PmWakeIR2[idx] = 0xff;
    }
    gstPMCfg.stPMWakeCfg.u8PmWakeIR2[0] = 0x46;
    gstPMCfg.stPMWakeCfg.u8PmStrMode = PM_DC_MODE; //standby

    //PowerDownCfg
    gstPMCfg.stPMPowerDownCfg.u8PowerDownMode = E_PM_STANDBY;
    gstPMCfg.stPMPowerDownCfg.u8WakeAddress = E_PM_LAST_TWOSTAGE_POWERDOWN; //two stage

    //SarCfg
    gstSARCfg.u8SARChID = 0x00;
    gstSARCfg.tSARChBnd.u8UpBnd = 0xff;
    gstSARCfg.tSARChBnd.u8LoBnd = 0xf0;
    gstSARCfg.u8KeyLevelNum = 0x08;

    gstSARCfg.u8KeyThreshold[0] = 0x10;
    gstSARCfg.u8KeyThreshold[1] = 0x2f;
    gstSARCfg.u8KeyThreshold[2] = 0x4d;
    gstSARCfg.u8KeyThreshold[3] = 0x71;
    gstSARCfg.u8KeyThreshold[4] = 0x92;
    gstSARCfg.u8KeyThreshold[5] = 0xab;
    gstSARCfg.u8KeyThreshold[6] = 0xc3;
    gstSARCfg.u8KeyThreshold[7] = 0xe7;

    gstSARCfg.u8KeyCode[0] = 0x46;
    gstSARCfg.u8KeyCode[1] = 0xa8;
    gstSARCfg.u8KeyCode[2] = 0xa4;
    gstSARCfg.u8KeyCode[3] = 0xa2;

    MDRV_PM_DEBUG("finish MDrv_PM_PMCfg_Init \n");
    return E_PM_OK;
}

void MDrv_PM_WakeIrqMask(u8 mask)
{
#ifdef CONFIG_KEYBOARD_MTK
    MHal_PM_WakeIrqMask(mask);
#endif
}
EXPORT_SYMBOL(MDrv_PM_WakeIrqMask);
//-------------------------------------------------------------------------------------------------
void MDrv_SetDram(u32 u32Addr, u32 u32Size)
{
    gPM_DramAddr = u32Addr;
    gPM_DramSize = u32Size;
}
EXPORT_SYMBOL(MDrv_SetDram);
//-------------------------------------------------------------------------------------------------
void MDrv_SetData(u32 u32Addr, u32 u32Size)
{
    gPM_DataAddr = u32Addr;
    gPM_DataSize = u32Size;
}
EXPORT_SYMBOL(MDrv_SetData);
PM_Result MDrv_PM_GetCfg(PM_Cfg_t* pstPMCfg)
{
    phys_addr_t *remap_addr = NULL;
    remap_addr = (phys_addr_t *)ioremap_wc(gPM_DataAddr + ARM_MIU0_BUS_BASE, gPM_DataSize);
    if (remap_addr == NULL)
    {
        MDRV_PM_DEBUG("ioremap_wc failed\n");
        return E_PM_FAIL;
    }

    memcpy((void*)&(pstPMCfg->stPMWakeCfg), (void*)remap_addr, sizeof(PM_WakeCfg_t));
    memcpy((void*)&(pstPMCfg->stPMPowerDownCfg), (void*)remap_addr + PM_OFFSET_POWER_DOWN, sizeof(PM_PowerDownCfg_t));

    iounmap(remap_addr);
    return E_PM_OK;
}

PM_Result MDrv_PM_SetCfg(PM_Cfg_t* pstPMCfg)
{
    phys_addr_t *remap_addr = NULL;
    int i = 0;
    remap_addr = (phys_addr_t *)ioremap_wc(gPM_DataAddr + ARM_MIU0_BUS_BASE, gPM_DataSize);
    if (remap_addr == NULL)
    {
        MDRV_PM_DEBUG("ioremap_wc failed\n");
        return E_PM_FAIL;
    }
    for(i=0; i<MAX_BUF_WAKE_IR; i++)
    {
        if( (pstPMCfg->stPMWakeCfg.u8PmWakeIR[i] == 0x46) || (pstPMCfg->stPMWakeCfg.u8PmWakeIR[i] == 0x03) || (pstPMCfg->stPMWakeCfg.u8PmWakeIR[i] == 0x0))
        {
            pstPMCfg->stPMWakeCfg.u8PmWakeIR[i] = 0x99;   //0x99 not be used, avoid conflict
        }
    }
    memcpy((void*)remap_addr, (void*)&(pstPMCfg->stPMWakeCfg), sizeof(PM_WakeCfg_t));
    memcpy((void*)remap_addr + PM_OFFSET_POWER_DOWN, (void*)&(pstPMCfg->stPMPowerDownCfg), sizeof(PM_PowerDownCfg_t));
    memcpy((void*)remap_addr + PM_OFFSET_IR_VER, (void*)&gstIrInfoCfg.u8IrVersion, sizeof(u8));
    memcpy((void*)remap_addr + PM_OFFSET_IR_NORMAL, (void*)&gstIrInfoCfg.u8NormalKeyNumber, IR_POWER_KEY_NORMAL_SIZE_MAX+1);
    memcpy((void*)remap_addr + PM_OFFSET_IR_EXTEND, (void*)&gstIrInfoCfg.u8ExtendKeyNumber, IR_POWER_KEY_EXTEND_SIZE_MAX+1);

    iounmap(remap_addr);
    return E_PM_OK;
}

#ifdef CONFIG_MSTAR_SYSFS_BACKLIGHT
PM_Result MDrv_PM_TurnoffBacklight(void)
{
    struct file *fp = NULL;
    char BACKLIGHT_BUFFER[] = "0";
    mm_segment_t fs;
    loff_t pos;

    MDRV_PM_DEBUG("start MDrv_PM_TurnoffBacklight\n");

    fp = filp_open("/sys/class/backlight/backlight/brightness", O_RDWR, 0);

    if (IS_ERR(fp)) {
        MDRV_PM_DEBUG("filp_open failed\n");
        return E_PM_FAIL;
    }
    fs = get_fs();
    set_fs(KERNEL_DS);
    pos = 0;
    vfs_write(fp, BACKLIGHT_BUFFER, strlen(BACKLIGHT_BUFFER), &pos);

    filp_close(fp, NULL);
    set_fs(fs);

    return E_PM_OK;
}
#endif

u8 MDrv_PM_GetWakeupSource(void)
{
    return MHal_PM_GetWakeupSource();
}


static int __init MDrv_PM_SetPMPath(char *str)
{
    if( str != NULL)
    {
        strncpy(pm_path, str, (CORENAME_MAX_SIZE-1));
        pm_path[sizeof(pm_path) - 1] = '\0';
        pm_path_exist = 1;
    }
    return 0;
}

static int __init MDrv_PM_Set_RTPM_Info(char *str)
{
    if (str != NULL)
    {
        sscanf(str, "%u, %llx", &gRTPM_Enable, &gRTPM_Addr);
    }
    return 0;
}

early_param("pm_path", MDrv_PM_SetPMPath);
early_param("RTPM_INFO", MDrv_PM_Set_RTPM_Info);
