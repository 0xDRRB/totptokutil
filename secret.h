#pragma once

/* This is public knowledge. This key is not secret !
 *
 * See : https://www.token2.com/site/page/tools-for-programmable-tokens
 *
 * "We use ready components for our cards (often called Java-chips) and
 * they have by default NFC access authentication, the access key was hard
 * coded , currently  "8A D20 688 3CA3 694 82 AB2 7182 B6E 832 24" for
 * single profile tokens (which cannot be changed) and "544 F4B 454 E32
 * 4D4 F4C 544 F31 2D4 B4 55 9" for multi-profile models (which can be
 * changed) ; removing authentication routine completely would make the
 * final cost of the products higher. While this does not compromise security
 * (as it is only possible to write the seeds and never read) , using a
 * wrong app will damage the card for this reason."
 */


unsigned char customerkey[16] = { 0x8A, 0xD2, 0x06, 0x88, 0x3C, 0xA3, 0x69, 0x48, 0x2A, 0xB2, 0x71, 0x82, 0xB6, 0xE8, 0x32, 0x24 };


