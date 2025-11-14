#Integer Overflow → Packet Length Truncation → Wire-Protocol Smuggling →
Unauthorized DB Insert → Login Bypass → Flag


- no account is initially created on the platform (i.e., there is no “admin/admin” or default user). So the exploit must create an account (insert a user document) or otherwise bypass login.
- The application utilized Rust, MongoDB, and the mongodb driver version 2.8.1
- The challenge was based on a specific vulnerability (CVE-2024-6382) present in the MongoDB driver. This bug occurs because the total message length calculated by the Rust driver is truncated to a signed 32-bit integer (i32) before being sent to the Mongo server.
- The core bug: When the driver sends a message to the Mongo server it computes a total_length as u32 (unsigned 32-bit), but then it casts/truncates to i32 (signed 32-bit) before sending. If you use a size of e.g. 2^32 = 4,294,967,296, the cast to i32 overflows and becomes 0. Thus a zero packet size is sent. 

- The Mongo server then parses the message length header and sees “0” (which is invalid) and treats the rest of the data in the TCP stream as raw extra data. 

- This opens the door for request smuggling, allowing the attacker to send a custom MongoDB operation

- The effect: This lets the attacker send a huge preamble (to overflow/underflow), then send a crafted BSON insert command buried in the extra raw data, effectively injecting a new user into the users collection (bypassing ordinary API logic).

*The integer overflow*

The MongoDB Rust driver calculates total_length as a u32 (unsigned 32-bit integer).

But before sending the packet, it casts that u32 into an i32 (signed 32-bit integer).

This cast is dangerous, because the value they compute is 4,294,967,296 (exactly 2³²).

A u32 is an unsigned 32-bit number:

Minimum: 0

Maximum: 4,294,967,295 (2³² − 1)

Capacity: 0 → 4,294,967,295

So these values are perfectly legal for u32.

The driver computes: total_length = 4,294,967,296   (which is 2^32)

But this number is NOT a valid u32 value (it is one more than the max allowed).

However, Rust does modular arithmetic on overflow.

So:

4,294,967,296 mod 2^32 = 0

So the u32 value wraps around to 0.

i32 is a signed 32-bit integer:

Minimum: −2,147,483,648

Maximum: +2,147,483,647

Anything outside this range cannot be represented directly.

So the cast truncates the bits.

But since the u32 value wrapped to 0, the i32 cast sees:
i32 value = 0

Why 4,294,967,296 becomes 0

Here is the binary explanation:
`2^32  = 1 00000000 00000000 00000000 00000000   (33 bits)`

A 32-bit type can store only the lower 32 bits, so the leading 1 is dropped:

00000000 00000000 00000000 00000000   → 0

So after truncation:

u32(4294967296) becomes: 0

And i32(0) is also: 0

MongoDB expects:

A positive packet length like 100, 500, etc.

Minimum allowed size is 16 bytes

But because of the overflow, the driver sends: length=0

MongoDB interprets this as:

“This packet is corrupt”

“Everything following it must be extra/garbage data”

But Mongo still reads the extra data from the wire

This allows the attacker to smuggle a second BSON command (e.g. an INSERT into users collection).


*BSON Constraint Bypass*

 A specific operational byte, `\xdd`, required for the insert BSON command, was typically disallowed in input. The exploit bypassed this by splitting the payload between the username and password fields, exploiting how BSON stores field size before content, which allowed the required \xdd byte to be included in the request stream.

*nop-sled*

- To trigger the integer overflow, the attacker must make the total MongoDB packet length exactly 2³² bytes (≈4 GB).

    But sending one giant 4GB MongoDB packet is:

    - NOT practical

    - NOT allowed by HTTP request limits

    - NOT possible directly from a browser

    - NOT possible because MongoDB messages have strict structure

So the attacker needs a way to slowly accumulate size until the message size reaches ~4GB.

That accumulation is done using many small valid MongoDB packets.
These packets do nothing useful.
They simply add to the total size.

**Exploit steps**

- Spot that the Rust MongoDB driver version is 2.8.1 (known CVE-2024-6382).

- Abuse the driver’s length calculation bug so that it sends a message with length 0 to Mongo.

- Use that to desync the MongoDB wire protocol and “smuggle” a custom BSON command.

- That custom BSON command is an insert into the users collection (u="admin", p="admin").

- Then just log in with admin/admin → get session → GET / → flag.

**exploit script**

exploit script in nosqli-solve/src/main.rs

to build:
```
cargo build --release
```
 this produces binary: target/release/generate_payload

to run the script:
```
./target/release/generate_payload
```
If successful, you will see:

username.bin created

password.bin created

Check them:
```
ls -lh
```
You will see huge files (~gigabytes).

You now have:

- username.bin → NOP sled + header

- password.bin → BSON insert command + padding

combine:
```
echo -n "username=" > payload
cat username.bin >> payload
echo -n "&password=" >> payload
cat password.bin >> payload
```

Because the payload is mostly zeros, gzip reduces it massively:
```
gzip -c payload > payload.gz
```
check size:
```
ls -lh payload.gz
```

run the payload:
```
curl -X POST http://localhost/login \
  -H "Content-Encoding: gzip" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-binary "@payload.gz"
```
If successful:

MongoDB gets desynchronized

The insert command gets processed

A new user {u:"admin", p:"admin"} is inserted

Login normally and get the flag.