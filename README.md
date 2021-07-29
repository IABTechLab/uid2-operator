# UID2 Operator


UID2 Project and its components are managed by the IAB Tech Lab Addressability Working Group and Privacy & Rearc Commit Group. Please review the governance guidelines [here](https://github.com/IABTechLab/uid2-core/blob/master/Software%20Development%20and%20Release%20Procedures.md)

## Prerequisite

To setup dependencies before building, run the follow script

```bash
./setup_dependencies.sh
```

## Building

To run unit tests:

```
mvn clean test
```

To package application:

```
mvn package
```

To run application:

- use `conf/local-config.json` to run standalone operator service 
  for local debugging, which loads salts, keys and optout from mock storage provider, and doesn't communicate with uid2-core and uid2-optout.

```
mvn clean compile exec:java -Dvertx-config-path=conf/local-config.json
```

- use `conf/integ-config.json` to run optout operator that
  integrates with uid2-core (default runs on `localhost:8088`) and uid2-optout  (default runs on `localhost:8081`)

```
mvn clean compile exec:java -Dvertx-config-path=conf/integ-config.json
```

# License

   Copyright (c) 2021 The Trade Desk, Inc

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.
   2. Redistributions in binary form must reproduce the above copyright notice,
      this list of conditions and the following disclaimer in the documentation
      and/or other materials provided with the distribution.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
   AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
   ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
   LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
   CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
   SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
   INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
   CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
   ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
   POSSIBILITY OF SUCH DAMAGE.

