# Third-Party Licenses

This document lists bundled third-party code and the corresponding license notices.

## Included Components

### md5.js
- Upstream: JavaScript MD5 implementation by Paul Johnston
- Copyright: Copyright (C) Paul Johnston 1999 - 2002
- Additional contributors named in source: Greg Holt, Andrew Kepert, Ydnar, Lostinet
- License family: BSD-style (as stated in source header)
- Source header:

```
A JavaScript implementation of the RSA Data Security, Inc. MD5 Message
Digest Algorithm, as defined in RFC 1321.
Version 2.1 Copyright (C) Paul Johnston 1999 - 2002.
Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
Distributed under the BSD License
See http://pajhome.org.uk/crypt/md5 for more info.
```

### domain-extractor.js
- Upstream: Stanford PwdHash code by Collin Jackson, with notes about adaptation from Chris Zarate's tool
- Copyright: Copyright 2005 Collin Jackson
- License: BSD 3-Clause (verbatim notice included in source)
- Verbatim notice:

```
Copyright 2005 Collin Jackson

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
    * Neither the name of Stanford University nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

### hashed-password.js
- Upstream: Stanford PwdHash code by Collin Jackson
- Copyright: Copyright 2005 Collin Jackson
- License: BSD 3-Clause (verbatim notice included in source)
- Verbatim notice:

```
Copyright 2005 Collin Jackson

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
    * Neither the name of Stanford University nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

## Notes

- This repository currently vendors dependency source files directly; there is no package-manager lockfile in the project root.
- If new dependencies are added later (npm, vendored JS, icons, fonts, etc.), add their notices to this file.
