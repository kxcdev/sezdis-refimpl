(presentation slides: [scis2024presentation-exported.pdf](./scis2024presentation-exported.pdf) (password is the WiFi password of D会場))

# Reference Implementation for SezDis Sealing

This repository holds the reference implementation code for
a concrete construction for the sealing scheme described in the
following paper to be presented at SCIS 2024:

SezDis Sealing: a Short, Eﬀicient, and Zero-Storage Distributed Sealing Scheme.

## Get Started

This implementation is written in TypeScript.
You can build it with `yarn` followed by `yarn build`
(assuming you have [Yarn the package manager](https://yarnpkg.com) installed.)

You can run the included tests with `yarn jest`
(assume that you have built the project first.)

If you are hacking around, you may find `yarn dev` and `yarn verify`
particularly interesting.

## Organization

- `src/sezdis-generic.ts` implements the generic SezDis scheme
  as annotated source code. The implementation mostly
  follow the description in the paper with one noticeable difference:
  `AD.verifier` is omitted and `D.tok` is directly derived as
  `KDF(K ++ D.id ++ A.secret)`.

  This is an early variant of the scheme and does not effect the
  effectiveness nor security properties of the scheme. `AD.verifier`
  is an optional feature to assist the registration process
  BEYOND what is necessary for SezDis itself, as discussed in the paper.

  It is recommanded that you start code reading from here,
  or alternatively take a look at a
  [frank implementation](https://github.com/kxcdev/sezdis-refimpl/blob/108e67d38e79eec3d091029c59640bb4226d6ef4/src/sezdis.test.ts#L130-L222)
  of the concrete scheme as part of the test suite.

- `src/sezdis-416a0.ts` implements a concrete construction of the
  SezDis scheme. `416a0` signifies the fact that it's the first
  published scheme (the `a0` part) that generates 416-bits seals.

- `src/node-crypto/node-sezdes416a0-prims.ts` gives an overview of
  all crypto primitives used to implement the `416a0` concrete scheme
  of SezDis.

- `src/sezdis.test.ts` and `src/node-*.test.ts` contain various tests
 to validate primitives as well as the `sezdis-416a0` implementation.

## License

This software is licensed under the Apache License version 2.0
by the copyright holder(s) listed below. See the [LICENSE](LICENSE) file for details.

Copyright 2023 Kotoi-Xie Consultancy, Inc.
