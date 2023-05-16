# OATH, like Open Authentication

Implements HOTP and TOTP algorithms according to [RFC 4226](https://www.rfc-editor.org/rfc/rfc4226), respectively [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238) and the [Key URI Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format) to make it more usable.

## Why?

I mean, there are plenty of related libraries our there. So why yet another one? Unfortunately, none of them felt sound (very subjective opinion). So, if you don't like it - that's fair. If you are still interested, head over to the next section.

## How to use

This library consists of two layers, the DIY layer, implementing the actual algorithms. Here you have to care by yourself about almost anything, hence the name DIY, and the All Inclusive layer - there are still some things, you have to care about, bot most of the stuff is abstracted away.

### DIY

This layer consists of three packages - `totp`, `hotp` and `otpauth`. As the names imply, they implement the corresponding functionality.

#### Generating & Verifying OTPs

The following example makes use of the TOTP algorithm. The usage of HOTP would look identical. The only difference is the configuration, as HOTP is based on counters and which values is used to generate, respectively validate the OTP value. Indeed, both implement the same `otp.Algorithm` interface.

```go
package main

import (
	"time"
	
	"github.com/dadrus/oath/otp"
	"github.com/dadrus/oath/totp"
)

func main()  {
	// Generate or import the key to be used
	key := ...
	// create an algorithm instance
	alg := totp.New(key,
		totp.WithHashAlgorithm(otp.SHA1),
		totp.WithDigits(6),
		totp.WithTimeStep(30 * time.Second), 
		totp.WithT0(0))
	// actually all the configuration options used above could be omitted
	// as they represent defaults

	// Generate the OTP value
	value := alg.Generate(time.Now().Unix())
	
	// Validate the OTP value
	deviation, err := alg.Validate(value, time.Now().Unix(), totp.WithSkew(1))
	if err != nil {
		// validation failed. Do something with the error
	}
	
	// validation succeed. Deviation is the amount of seconds, the provided
	// time stamp deviates from the time stamp used to generate the OTP value
	
	// The last parameter in the Validation call above is optional.
	// it defines how big the sliding window for validation should be.
	// For TOTP, the value 1 means, one step in the past and one in the future.
}
```

Even the example above is pretty simple, there are many topics, which should be addressed by the application using it:

* how to protect the key used by the algorithm
* how to deal with deviation, as well as the counter in case of HOTP
* how to deal with synchronization between the client and the server
* how to ensure OTPs are not reused
* ...

These questions bring us to the All Inclusive layer

#### Export the key and the configuration

This section is not about the All Inclusive stuff. That will come later. This section deals with the rare requirement to export the key and the algorithm setting, so that an OTP App, like FreeOTP, Google Authenticator, 2FAS and Co can be used with a service making use of this library. Here again an example:

```go
import (
	"image/png"
	
	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
	
	"github.com/dadrus/oath/otpauth"
)

func main() {
	// get the algorithm instance from somewhere (see e.g. the previous example)
	alg := ...
	
	// encode the settings of the algorithm, plus the name of the account, the algorithm
	// has been configured for, as well as optionally the name if the issuer
	otpURI := otpauth.ToURI(alg, "my account", otpauth.WithIssuer("my fancy service"))
	
	// encode it now as QR Code and stream somewhere
	// E.g.
	b, _ := qr.Encode(otpURI, qr.M, qr.Auto)
	b, _ = barcode.Scale(b, 200, 200)
	
	png.Encode(writer, b)
}
```

### All Inclusive

This layer tries to offer a very simple API to overcome the challenges written above. Example:

```go
import (
	"time"
	
	"github.com/dadrus/oath"
	"github.com/dadrus/oath/otp"
)

func main() {
	// using  symmetric key instantiate an AEAD cipher
	c := ...
	
	// create a TOTP blob. 
	blob, err := oath.TOTP.New(c,
		oath.WithHashAlgorithm(otp.SHA256), 
		oath.WithDigits(6), 
		oath.WithTimeStep(20 * time.Second), 
		oath.WithSkew(1))
	if err != nil {
	    // Do something with the error 
	}
	
	// The blob returned above is just a string, which is contains all the algorithms 
	// settings encrypted and authenticity protected by the AEAD cipher. So you can 
	// store it in the DB together with the remaining profile information of the user.
	
	// All configuration options above are optional. Even the key used for the actual OTP
	// generation and verification. If not provided (as done above), it will be generated.
	
	// Verify an OTP received from the cleint
	serialized, synced, err := oath.Verify(otpValue, blob, c)
	
	// serialized is an updated version of the blob (validity window, used OTPs, etc). 
	// As with the blob from above it is encrypted and authenticity protected by the AEAD
	// cipher
	
	// synced will be set to true if there was at least one successful verification (also
	// in the past for the given blob). This way you can better react on errors, e.g during
	// registration, onoarding, etc.
	
	// Export the blob for usage with OTP Apps 
	otpURI, encodedKey, err := oath.Export(serialized, c, "my account", "my fancy service")
	
	// This is pretty much the same as with the DIY layer. The difference is that you get
	// also the key used for the OTP validation as base32 encoded string. So you can render 
	// it as text in addition to the QR code
}
```

Compared to the DIY layer, the only thing you have to care about is the key material used to encrypt the blob and of course the blob itself - where to store it.


