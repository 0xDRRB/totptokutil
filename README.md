# TOTPtokutil
TOTP Token utility

This program allows you to configure TOTP programmable tokens from [Token2](https://www.token2.eu/shop/category/programmable-tokens) over NFC (and probably those from ExcelSecu as well).

This tool is in alpha version and has only been tested with C302-i and OTPC-P2-i tokens. It allows to configure the seed (provided in base32 format) used by the token as well as the other settings (HMAC type, date/time, TOTP period and display timeout).

The base32 decode code is inspired by *fmount*'s [c_otp](https://github.com/fmount/c_otp) and the SM4 cipher functions are the work of [siddontang](https://github.com/siddontang/pygmcrypto). This program only depends on [LibNFC](https://github.com/nfc-tools/libnfc).

****WARNING !*** Programming the configuration in the tag is done after an authentication phase requiring a 128-bit key. The key is defined `secret.h` and the one included with this code is that of Token2 (as specified on the ["Tools for hardware tokens and security keys"](https://www.token2.eu/site/page/tools-for-programmable-tokens) page of their website). **Do not use this key with tokens that do not come from Token2!** Several failed authentication attempts can lock the token permanently.

**THIS SOFTWARE COMES WITH NO WARRANTIES, USE AT YOUR OWN RISK**. It works for me, with my tokens. But don't blame me if you make your tokens unusable. You have been warned.

