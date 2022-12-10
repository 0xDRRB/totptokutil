# TOTPtokutil
TOTP Token utility

This program allows you to configure TOTP programmable tokens from [Token2](https://www.token2.eu/shop/category/programmable-tokens) over NFC (and probably those from ExcelSecu as well).

This tool is in alpha version and has been tested with C302-i and OTPC-P2-i tokens ([eSecuOTP-1A from ExcelSecu](https://www.excelsecu.com/productdetail/esecuotptoken26.html) has also been tested without problems - 2022/12/10). It allows you to configure the seed (provided in base32 format) used by the token as well as the other settings (HMAC type, date/time, TOTP period and display timeout).

The base32 decode code is inspired by *fmount*'s [c_otp](https://github.com/fmount/c_otp) and the SM4 cipher functions are the work of [siddontang](https://github.com/siddontang/pygmcrypto). This program only depends on [LibNFC](https://github.com/nfc-tools/libnfc).

****WARNING !*** Programming the configuration in the tag is done after an authentication phase requiring a 128-bit key. The key is stored in `secret.key` binary file and the one included with this code is that of Token2 (as specified on the ["Tools for hardware tokens and security keys"](https://www.token2.eu/site/page/tools-for-programmable-tokens) page of their website). **Do not use this key with tokens that do not come from Token2!**. Several failed authentication attempts can lock the token permanently. You can create your `secret.key` from a hex string with a command like `echo -n "8AD206883CA369482AB27182B6E83224" | xxd -r -p - > secret.key`. You can set a specific binary keyfile with `-f` (default is `secret.key`).

**THIS SOFTWARE COMES WITH NO WARRANTIES, USE AT YOUR OWN RISK**. It works for me, with my tokens. But don't blame me if you make your tokens unusable. You have been warned.

