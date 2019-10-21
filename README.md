# Simple Polymorphic Engine — SPE32

**Simple Polymorphic Engine (SPE32)** is a simple polymorphic engine
for encrypting code and data.

SPE32 allows you to encrypt any data and generate a **unique**
decryption code for this data. The encryption algorithm uses
randomly selected instructions and encryption keys.

The generated decryption code will be different each time.

## Polymorphic decryption code as viewed in x86dbg debugger

![Polymorphic code in x86dbg debugger](https://www.pelock.com/img/en/products/simple-polymorphic-engine/simple-polymorphic-engine-spe32-poly-engine-x86dbg-debugger-1.png)

## Another polymorphic code mutation, this time with junk instructions

![Polymorphic code in x86dbg debugger with junk instructions](https://www.pelock.com/img/en/products/simple-polymorphic-engine/simple-polymorphic-engine-spe32-poly-engine-x86dbg-debugger-junk-code-2.png)

## SPE32 features and status

The SPE32 engine is an amateur project that can be used to demonstrate what
polymorphic engines are. I wrote it some time ago, but I thought
it would be a good idea to make it public.

The entire code was written in a **32-bit assembler** for the [MASM compiler](http://www.masm32.com/).

Features:

* entire code is position independent (delta offset is used to access data)
* XOR, ADD, SUB used for encryption
* junk opcodes generation - ADD,ADC,SUB,SBB,ROL,ROR,RCR,RCL,SHL,SHR,NOT,NEG,DEC,INC

I don't provide technical support for SPE32, use it at your own risk.

## Fully fledged commercial polymorphic engine

If you are looking for professional solution take a look at our **Poly Polymorphic Engine**.

* https://www.pelock.com/products/poly-polymorphic-engine

Poly Polymorphic Engine is the **only commercial polymorphic engine** available on the market.
It's a highly specialized cryptographic solution which is used in anti-cracking software
protection systems and anti-reverse engineering systems. Due to the complicated nature of
their code, polymorphic engines aren't publicly available, and creating one requires
highly specialized knowledge in low level assembly programming and reverse engineering
as well as an extensive testing process.

![Poly Polymorphic Engine](https://www.pelock.com/img/en/products/poly-polymorphic-engine/poly-polymorphic-engine.svg)

Bartosz Wójcik

- Visit our site at https://www.pelock.com
- Twitter https://twitter.com/PELock