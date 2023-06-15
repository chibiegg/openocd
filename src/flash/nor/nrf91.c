// SPDX-License-Identifier: GPL-2.0-or-later

/*******************************************************
 *   Copyright (C) 2020 I-SYST inc.                    *
 *   hnhoan@i-syst.com                                 *
 *                                                     *
 *   Copyright (C) 2023 by Yota Egusa (chibiegg)       *
 *   chibiegg@chibiegg.net                             *
 *******************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "imp.h"
#include <target/algorithm.h>
#include <target/armv7m.h>
#include <helper/types.h>
#include <helper/time_support.h>

#define NRF91_FLASH_BASE			0x00000000

// Factory Information Configuration Registers
#define NRF91_FICR_BASE				0x00ff0000
#define NRF91_FICR_DEVICEID0		(NRF91_FICR_BASE + 0x204)
#define NRF91_FICR_DEVICEID1		(NRF91_FICR_BASE + 0x208)
#define NRF91_FICR_INFO_PART		(NRF91_FICR_BASE + 0x20C)
#define NRF91_FICR_INFO_VARIANT		(NRF91_FICR_BASE + 0x210)
#define NRF91_FICR_INFO_PACKAGE		(NRF91_FICR_BASE + 0x214)
#define NRF91_FICR_INFO_RAM			(NRF91_FICR_BASE + 0x218)
#define NRF91_FICR_INFO_FLASH		(NRF91_FICR_BASE + 0x21C)
#define NRF91_FICR_CODEPAGESIZE		(NRF91_FICR_BASE + 0x220)
#define NRF91_FICR_CODESIZE			(NRF91_FICR_BASE + 0x224)
#define NRF91_FICR_DEVICETYPE		(NRF91_FICR_BASE + 0x228)

// User Information Configuration Regsters
#define NRF91_UICR_BASE				0x00ff8000
#define NRF91_UICR_APPROTECT		(NRF91_UICR_BASE + 0x000)
#define NRF91_UICR_SECUREAPPROTECT	(NRF91_UICR_BASE + 0x02C)
#define NRF91_UICR_ERASEPROTECT		(NRF91_UICR_BASE + 0x030)

// Non-Volatile Memory Controller Registers
#define NRF91_NVMC_BASE				0x50039000
#define NRF91_NVMC_BASE_NS			0x40039000

#define NRF91_NVMC_READY			(NRF91_NVMC_BASE + 0x400)
#define NRF91_NVMC_CONFIG			(NRF91_NVMC_BASE + 0x504)
#define NRF91_NVMC_ERASEALL			(NRF91_NVMC_BASE + 0x50C)
#define NRF91_NVMC_ERASEUICR		(NRF91_NVMC_BASE + 0x514)

#define NRF91_NVMC_CONFIG_REN		0
#define NRF91_NVMC_CONFIG_WEN		1
#define NRF91_NVMC_CONFIG_EEN		2

#pragma pack(push, 4)
typedef struct nrf_ficr_info {
	uint64_t id;
	uint32_t part;
	uint32_t variant;
	uint32_t package;
	uint32_t ram;
	uint32_t flash;
	uint32_t code_page_size;
	uint32_t code_size;
	uint32_t device_type;
} nrf_ficr_info_t;
#pragma pack(pop)

typedef struct nrf91_chip {
	uint32_t refcount;
	bool probed;
	bool ficr_info_valid;
	nrf_ficr_info_t ficr_info;
	uint32_t flash_size_kb;
	uint32_t ram_size_kb;
	struct target *target;
} nrf91_chip_t;

const struct flash_driver nrf91_flash;

static int nrf91_probe(struct flash_bank *bank);

static nrf91_chip_t *get_active_chip(struct flash_bank *bank)
{
	if (bank->target->state != TARGET_HALTED) {
		LOG_ERROR("Target not halted");
		return NULL;
	}

	nrf91_chip_t *chip = bank->driver_priv;

	if (chip->probed)
		return chip;

	if (nrf91_probe(bank) == ERROR_OK)
		return chip;

	return NULL;
}

static int nrf91_wait_for_nvmc(nrf91_chip_t *chip)
{
	uint32_t ready;
	int res;
	int timeout_ms = 340;
	int64_t ts_start = timeval_ms();

	do {
		res = target_read_u32(chip->target, NRF91_NVMC_READY, &ready);
		if (res != ERROR_OK)
			LOG_INFO("Couldn't read NRF91 NVME READY registers");

		if (ready == 0x00000001)
			return ERROR_OK;

		keep_alive();

	} while ((timeval_ms() - ts_start) < timeout_ms);

	LOG_DEBUG("Timed out waiting for NVMC_READY");
	return ERROR_FLASH_BUSY;
}

static int nrf91_nvmc_erase_enable(nrf91_chip_t *chip)
{
	int res;
	res = target_write_u32(chip->target,
			       NRF91_NVMC_CONFIG,
			       NRF91_NVMC_CONFIG_EEN);//|NRF91_NVMC_CONFIG_WEN);

	if (res != ERROR_OK) {
		LOG_ERROR("Failed to enable erase operation");
		return res;
	}

	/*
	  According to NVMC examples in Nordic SDK busy status must be
	  checked after writing to NVMC_CONFIG
	 */
	res = nrf91_wait_for_nvmc(chip);
	if (res != ERROR_OK)
		LOG_ERROR("Erase enable did not complete");

	return res;
}

static int nrf91_nvmc_write_enable(nrf91_chip_t *chip)
{
	int res;
	res = target_write_u32(chip->target,
			       NRF91_NVMC_CONFIG,
			       NRF91_NVMC_CONFIG_WEN);

	if (res != ERROR_OK) {
		LOG_ERROR("Failed to enable write operation");
		return res;
	}

	/*
	  According to NVMC examples in Nordic SDK busy status must be
	  checked after writing to NVMC_CONFIG
	 */
	res = nrf91_wait_for_nvmc(chip);
	if (res != ERROR_OK)
		LOG_ERROR("Write enable did not complete");

	return res;
}

static int nrf91_nvmc_read_only(nrf91_chip_t *chip)
{
	int res;
	res = target_write_u32(chip->target,
			       NRF91_NVMC_CONFIG,
			       NRF91_NVMC_CONFIG_REN);

	if (res != ERROR_OK) {
		LOG_ERROR("Failed to enable read-only operation");
		return res;
	}
	/*
	  According to NVMC examples in Nordic SDK busy status must be
	  checked after writing to NVMC_CONFIG
	 */
	res = nrf91_wait_for_nvmc(chip);
	if (res != ERROR_OK)
		LOG_ERROR("Read only enable did not complete");

	return res;
}

static void read_ficr_from_buffer(struct target *target, uint8_t *buf, nrf_ficr_info_t *ficr)
{
	ficr->id = target_buffer_get_u64(target, buf);
	buf += 8;
	ficr->part = target_buffer_get_u32(target, buf);
	buf += 4;
	ficr->variant = target_buffer_get_u32(target, buf);
	buf += 4;
	ficr->package = target_buffer_get_u32(target, buf);
	buf += 4;
	ficr->ram = target_buffer_get_u32(target, buf);
	buf += 4;
	ficr->flash = target_buffer_get_u32(target, buf);
	buf += 4;
	ficr->code_page_size = target_buffer_get_u32(target, buf);
	buf += 4;
	ficr->code_size = target_buffer_get_u32(target, buf);
}

static int nrf91_read_ficr_info(nrf91_chip_t *chip)
{
	int res;
	nrf_ficr_info_t ficr;
	uint8_t ficr_buf[sizeof(nrf_ficr_info_t)];

	chip->ficr_info_valid = false;

	res = target_read_buffer(chip->target, NRF91_FICR_DEVICEID0, sizeof(nrf_ficr_info_t), ficr_buf);
	if (res != ERROR_OK) {
		LOG_INFO("Couldn't read FICR INFO registers");
		return res;
	}
	read_ficr_from_buffer(chip->target, ficr_buf, &ficr);

	if (ficr.part != 0x9160 && ficr.part != 0x9120) {
		LOG_INFO("Wrong device %X", ficr.part);
		res = target_read_u32(chip->target, NRF91_FICR_INFO_PART, &ficr.part);
		if (res != ERROR_OK)
			LOG_INFO("Couldn't read FICR INFO registers");

		LOG_INFO("PART %X", ficr.part);

		return ERROR_FAIL;
	}

	memcpy(&chip->ficr_info, &ficr, sizeof(nrf_ficr_info_t));

	chip->ram_size_kb = ficr.ram;
	chip->flash_size_kb = ficr.flash;

	chip->ficr_info_valid = true;

	return ERROR_OK;
}

static int nrf91_info(struct flash_bank *bank, struct command_invocation *cmd)
{
	nrf91_chip_t *chip = bank->driver_priv;
	int res = ERROR_OK;

	if (!chip->ficr_info_valid)
		res = nrf91_read_ficr_info(chip);

	if (res == ERROR_OK) {
		char variant[5];
		memcpy(variant, &chip->ficr_info.variant, 4);
		variant[4] = 0;
		command_print_sameline(cmd,
				"nRF%X-%s, %uKB FLASH, %uKB RAM, DevId : 0x%016" PRIX64,
				chip->ficr_info.part, variant,
				chip->ficr_info.flash, chip->ficr_info.ram,
				chip->ficr_info.id);
	}

	return res;
}

static int nrf91_probe(struct flash_bank *bank)
{
	nrf91_chip_t *chip = bank->driver_priv;

	(void)nrf91_read_ficr_info(chip);

	if (!chip->ficr_info_valid) {
		LOG_INFO("Unknown device");
		return ERROR_FAIL;
	}

	free(bank->sectors);

	if (bank->base == NRF91_FLASH_BASE) {
		/* Sanity check */
		if (chip->ficr_info_valid && chip->flash_size_kb != chip->ficr_info.flash)
			LOG_WARNING("Chip's reported Flash capacity does not match FICR INFO.FLASH");

		bank->num_sectors = chip->ficr_info.code_size;
		bank->size = bank->num_sectors * chip->ficr_info.code_page_size;

		bank->sectors = alloc_block_array(0, chip->ficr_info.code_page_size, bank->num_sectors);
		if (!bank->sectors)
			return ERROR_FAIL;

		chip->probed = true;

	} else {
		bank->num_sectors = 1;
		bank->size = chip->ficr_info.code_page_size;

		bank->sectors = alloc_block_array(0, chip->ficr_info.code_page_size, bank->num_sectors);
		if (!bank->sectors)
			return ERROR_FAIL;

		bank->sectors[0].is_protected = 0;

		chip->probed = true;
	}

	return ERROR_OK;
}

static int nrf91_auto_probe(struct flash_bank *bank)
{
	nrf91_chip_t *chip = bank->driver_priv;

	if (!chip)
		return ERROR_FAIL;

	if (!chip->probed)
		return nrf91_probe(bank);

	return ERROR_OK;
}

static int nrf91_erase_all(nrf91_chip_t *chip)
{
	int res = nrf91_nvmc_erase_enable(chip);
	if (res == ERROR_OK) {
		res = target_write_u32(chip->target, NRF91_NVMC_ERASEALL, 1);
		res = nrf91_wait_for_nvmc(chip);
		nrf91_nvmc_read_only(chip);
	}
	return res;
}

static int nrf91_erase_page(struct flash_bank *bank,
							nrf91_chip_t *chip,
							struct flash_sector *sector)
{
	int res;

	res = nrf91_nvmc_erase_enable(chip);
	if (res == ERROR_OK) {
		res = target_write_u32(chip->target, sector->offset, 0xFFFFFFFF);
		if (res == ERROR_OK)
			res = nrf91_wait_for_nvmc(chip);

		return nrf91_nvmc_read_only(chip);
	}
	LOG_ERROR("** Failed to erase reg: 0x%08" PRIx32 " val: 0x%08" PRIx32,
			sector->offset, 0xFFFFFFFF);

	return res;
}

static int nrf91_write(struct flash_bank *bank, const uint8_t *buffer,
					uint32_t offset, uint32_t count)
{
	nrf91_chip_t *chip = get_active_chip(bank);
	int res;

	if (!chip)
		return ERROR_FAIL;

	assert(offset % 4 == 0);
	assert(count % 4 == 0);

	res = nrf91_nvmc_write_enable(chip);
	if (res != ERROR_OK) {
		LOG_ERROR("Failed to enable write to nrf91 flash");
		return res;
	}
	res = target_write_buffer(chip->target, bank->base + offset, count, buffer);
	if (res != ERROR_OK)
		LOG_ERROR("nrf91 write failed");

	nrf91_nvmc_read_only(chip);

	return res;
}

static int nrf91_erase(struct flash_bank *bank, unsigned int first, unsigned int last)
{
	int res = ERROR_OK;
	nrf91_chip_t *chip = get_active_chip(bank);

	if (!chip)
		return ERROR_FAIL;

	/* For each sector to be erased */
	for (unsigned int s = first; s <= last && res == ERROR_OK; s++)
		res = nrf91_erase_page(bank, chip, &bank->sectors[s]);

	return res;
}

static void nrf91_free_driver_priv(struct flash_bank *bank)
{
	nrf91_chip_t *chip = bank->driver_priv;
	if (!chip)
		return;

	chip->refcount--;
	if (chip->refcount == 0) {
		free(chip);
		bank->driver_priv = NULL;
	}
}

FLASH_BANK_COMMAND_HANDLER(nrf91_flash_bank_command)
{
	struct flash_bank *bank_iter;
	nrf91_chip_t *chip = NULL;

	if (bank->base != NRF91_FLASH_BASE && bank->base != NRF91_UICR_BASE) {
		LOG_ERROR("Invalid bank address " TARGET_ADDR_FMT, bank->base);
		return ERROR_FAIL;
	}

	/* iterate over nrf9 banks of same target */
	for (bank_iter = flash_bank_list(); bank_iter; bank_iter = bank_iter->next) {
		if (bank_iter->driver == &nrf91_flash && bank_iter->target == bank->target)
			chip = bank_iter->driver_priv;
	}

	if (!chip) {
		/* Create a new chip */
		chip = calloc(1, sizeof(*chip));
		if (!chip)
			return ERROR_FAIL;

		chip->target = bank->target;
	}

	chip->refcount++;
	chip->probed = false;
	bank->driver_priv = chip;
	bank->write_start_alignment = 4;
	bank->write_end_alignment = 4;

	return ERROR_OK;
}

COMMAND_HANDLER(nrf91_handle_mass_erase_command)
{
	int res;
	struct flash_bank *bank = NULL;
	struct target *target = get_current_target(CMD_CTX);

	res = get_flash_bank_by_addr(target, NRF91_FLASH_BASE, true, &bank);
	if (res != ERROR_OK)
		return res;

	assert(bank);

	nrf91_chip_t *chip = get_active_chip(bank);
	if (!chip)
		return ERROR_FAIL;

	res = nrf91_erase_all(chip);
	if (res != ERROR_OK) {
		LOG_ERROR("Failed to erase the chip");
		return res;
	}

	res = get_flash_bank_by_addr(target, NRF91_UICR_BASE, true, &bank);
	if (res != ERROR_OK)
		return res;

	return ERROR_OK;
}

static const struct command_registration nrf91_command_handlers[] = {
	{
		.name		= "mass_erase",
		.handler	= nrf91_handle_mass_erase_command,
		.mode		= COMMAND_EXEC,
		.help		= "Erase all flash contents of the chip.",
		.usage		= "",
	},
	COMMAND_REGISTRATION_DONE
};

const struct flash_driver nrf91_flash = {
	.name			= "nrf91",
	.commands		= nrf91_command_handlers,
	.flash_bank_command	= nrf91_flash_bank_command,
	.info			= nrf91_info,
	.erase			= nrf91_erase,
	.write			= nrf91_write,
	.read			= default_flash_read,
	.probe			= nrf91_probe,
	.auto_probe		= nrf91_auto_probe,
	.erase_check		= default_flash_blank_check,
	.free_driver_priv	= nrf91_free_driver_priv,
};
