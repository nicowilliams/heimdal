# Heimdal's ASN.1 Compiler

This is a new README, and it's not very rich in contents yet.  There are
companion README files in the same directory that are chock-full of
information -- be sure to read them!

## Table of Contents

 1. [Introduction](#Introduction)
 2. [News](#News)
 3. [Features](#Features)
 4. [Limitations](#Limitations)
 4. [Usage](#Usage)
 5. [Implementation](#implementation)
 6. [Moving From C](#moving-from-c)

## Introduction

ASN.1 is a... some would say baroque, perhaps obsolete, archaic even, "syntax"
for expressing data type schemas, and also a set of "encoding rules" (ERs) that
specify many ways to encode values of those types.

ASN.1 is a wheel that everyone loves to reinvent, and often badly.  It's worth
knowing a bit about it before reinventing this wheel yet again.

First, an example:

```ASN.1
-- This is what a certificate looks like (as in TLS server certificates, or
-- "SSL certs):
Certificate  ::=  SEQUENCE  {
     tbsCertificate       TBSCertificate,
     signatureAlgorithm   AlgorithmIdentifier,
     signatureValue       BIT STRING
}

-- The main body of a certificate is here though:
TBSCertificate  ::=  SEQUENCE  {
     version         [0]  Version DEFAULT 1,
     serialNumber         CertificateSerialNumber,
     signature            AlgorithmIdentifier,
     issuer               Name,
     validity             Validity,
     subject              Name,
     subjectPublicKeyInfo SubjectPublicKeyInfo,
     issuerUniqueID  [1]  IMPLICIT BIT STRING OPTIONAL,
     subjectUniqueID [2]  IMPLICIT BIT STRING OPTIONAL,
     extensions      [3]  EXPLICIT Extensions OPTIONAL
}
```

Those `[0]` things are called tags and are decidedly obsolete, along with all
"tag-length-value" (TLV) or "self-describing" encoding rules, and they appear
as lexical tokens in ASN.1 modules only because automatic tagging wasn't
invented and implemented until it was too late.  Though since no obsolete
technologies this widely used ever get retired completely, we have to support
them.

Encoding rules?  There are many:

 - JSON Encoding Rules (JER) (X.697)

   Use JSON instead of some binary scheme like DER (see below).

 - XML Encoding Rules (XER)

 - Generic String Encoding Rules (GSER) [RFC2641]

 - Basic, Distinguished, and Canonical Encoding Rules (BER, DER, CER) [X.690]

   These are the dreaded tag-length-value encoding rules.  They are redundant,
   wasteful, and inefficient in spite of being non-textual (i.e., binary)!

   The descriptor "tag-length-value" is due to all values being encoded as some
   bytes for a "tag", then some bytes for the length of the encoded value, then
   the encoded value itself.  The body of a structured type (e.g.,
   `Certificate`) is itself a concatenation of the TLV encodings of the fields
   of that structured type, in order.

   DER and CER are alternative canonical forms of BER.

 - Packed Encoding Rules (PER) and Octet Encoding Rules (OER)

   These are a lot like eXternal Data Representation (XDR), but with 1-octet
   alignment instead of 4-octet alignment.

Heimdal currently only supports DER for encoding, and DER and BER for decoding,
but soon may support JER as well.

## News

In recent times the following features have been added:

 - Feature parity for the "template" backend, even superiority, as the codegen
   backend does not yet support automatic open type decoding/encoding.

 - IMPLICIT tagging support is finally complete.

 - Automatic open type traversal, using a subset of X.681/X.682/X.683 for
   expressing the requisite metadata.

## Futures

 - JER support?

 - XDR/OER support?

 - Generate comparators?  (lib/hx509 has a half-baked Certificate comparator)

## Features

 - Most of X.680 is supported.

 - Most of X.690 is supported for decoding, with only DER supported for
   encoding.

 - We have an `asn1_print` program that can decode DER from any exported types
   from any ASN.1 modules committed in Heimdal:

   ```bash
   $ ./asn1_print ek.crt Certificate |
     jq '.tbsCertificate.extensions[3]._extnValue[]._values'
   ```

   ```JSON
   [
     {
       "_type": "TPMSpecification",
       "family": "2.0",
       "level": "0",
       "revision": "138"
     }
   ]
   [
     {
       "_type": "TPMSecurityAssertions",
       "version": "0",
       "fieldUpgradable": true,
       "ekGenerationType": "655617",
       "ekGenerationLocation": "655616",
       "ekCertificateGenerationLocation": "655616",
       "ccInfo": {
         "_type": "CommonCriteriaMeasures",
         "version": "3.1",
         "assurancelevel": "4",
         "evaluationStatus": "2",
         "plus": true,
         "strengthOfFunction": null,
         "profileOid": null,
         "profileUri": null,
         "targetOid": null,
         "targetUri": null
       },
       "fipsLevel": {
         "_type": "FIPSLevel",
         "version": "140-2",
         "level": "2",
         "plus": false
       },
       "iso9000Certified": false,
       "iso9000Uri": null
     }
   ]
   ```

   A complete dump of such a certificate:

   ```bash
   $ ./asn1_print ek.crt Certificate | jq .
   ```

   ```JSON
   {
     "_type": "Certificate",
     "tbsCertificate": {
       "_type": "TBSCertificate",
       "_save": "30820376A00302010202146A0597BA71D7E6D3AC0EDC9EDC95A15B998DE40A300D06092A864886F70D01010B05003055310B3009060355040613024348311E301C060355040A131553544D6963726F656C656374726F6E696373204E56312630240603550403131D53544D2054504D20454B20496E7465726D656469617465204341203035301E170D3138313231343030303030305A170D3238313231343030303030305A300030820122300D06092A864886F70D01010105000382010F003082010A0282010100CC14EB27A78CEB0EA486FA2DF7835F5FA8E905B097012B5BDE50380C355B1A2A721BBC3D08DD21796CDB239FA95310651B1B56FD2CFE53C87352EBD996E33256160404CE9302A08066801E786A2F86E181F949966F492A85B58EAA4A6A8CB3697551BB236E87CC7BF8EC1347871C91E15437E8F266BF1EA5EB271FDCF374D8B47DF8BCE89E1FAD61C2A088CB4036B359CB72A294973FEDCCF0C340AFFD14B64F041165581ACA34147C1C75617047058F7ED7D603E032508094FA73E8B9153DA3BF255D2CBBC5DF301BA8F74D198BEBCE86040FC1D2927C7657414490D802F482F3EBF2DE35EE149A1A6DE8D16891FBFBA02A18AFE59F9D6F149744E5F0D559B10203010001A38201A9308201A5301F0603551D230418301680141ADB994AB58BE57A0CC9B900E7851E1A43C0866030420603551D20043B303930370604551D2000302F302D06082B060105050702011621687474703A2F2F7777772E73742E636F6D2F54504D2F7265706F7369746F72792F30590603551D110101FF044F304DA44B304931163014060567810502010C0B69643A353335343444323031173015060567810502020C0C53543333485450484148433031163014060567810502030C0B69643A303034393030303830670603551D090460305E301706056781050210310E300C0C03322E300201000202008A304306056781050212313A30380201000101FFA0030A0101A1030A0100A2030A0100A310300E1603332E310A01040A01020101FFA40F300D16053134302D320A0102010100300E0603551D0F0101FF040403020520300C0603551D130101FF0402300030100603551D250409300706056781050801304A06082B06010505070101043E303C303A06082B06010505073002862E687474703A2F2F7365637572652E676C6F62616C7369676E2E636F6D2F73746D74706D656B696E7430352E637274",
       "version": "2",
       "serialNumber": "6A0597BA71D7E6D3AC0EDC9EDC95A15B998DE40A",
       "signature": {
         "_type": "AlgorithmIdentifier",
         "algorithm": {
           "_type": "OBJECT IDENTIFIER",
           "oid": "1.2.840.113549.1.1.11",
           "components": [
             1,
             2,
             840,
             113549,
             1,
             1,
             11
           ],
           "name": "id-pkcs1-sha256WithRSAEncryption"
         },
         "parameters": "0500"
       },
       "issuer": {
         "_choice": "rdnSequence",
         "value": [
           [
             {
               "_type": "AttributeTypeAndValue",
               "type": {
                 "_type": "OBJECT IDENTIFIER",
                 "oid": "2.5.4.6",
                 "components": [
                   2,
                   5,
                   4,
                   6
                 ],
                 "name": "id-at-countryName"
               },
               "value": {
                 "_choice": "printableString",
                 "value": "CH"
               }
             }
           ],
           [
             {
               "_type": "AttributeTypeAndValue",
               "type": {
                 "_type": "OBJECT IDENTIFIER",
                 "oid": "2.5.4.10",
                 "components": [
                   2,
                   5,
                   4,
                   10
                 ],
                 "name": "id-at-organizationName"
               },
               "value": {
                 "_choice": "printableString",
                 "value": "STMicroelectronics NV"
               }
             }
           ],
           [
             {
               "_type": "AttributeTypeAndValue",
               "type": {
                 "_type": "OBJECT IDENTIFIER",
                 "oid": "2.5.4.3",
                 "components": [
                   2,
                   5,
                   4,
                   3
                 ],
                 "name": "id-at-commonName"
               },
               "value": {
                 "_choice": "printableString",
                 "value": "STM TPM EK Intermediate CA 05"
               }
             }
           ]
         ]
       },
       "validity": {
         "_type": "Validity",
         "notBefore": {
           "_choice": "utcTime",
           "value": "2018-12-14T00:00:00Z"
         },
         "notAfter": {
           "_choice": "utcTime",
           "value": "2028-12-14T00:00:00Z"
         }
       },
       "subject": {
         "_choice": "rdnSequence",
         "value": []
       },
       "subjectPublicKeyInfo": {
         "_type": "SubjectPublicKeyInfo",
         "algorithm": {
           "_type": "AlgorithmIdentifier",
           "algorithm": {
             "_type": "OBJECT IDENTIFIER",
             "oid": "1.2.840.113549.1.1.1",
             "components": [
               1,
               2,
               840,
               113549,
               1,
               1,
               1
             ],
             "name": "id-pkcs1-rsaEncryption"
           },
           "parameters": "0500"
         },
         "subjectPublicKey": "2160:3082010A0282010100CC14EB27A78CEB0EA486FA2DF7835F5FA8E905B097012B5BDE50380C355B1A2A721BBC3D08DD21796CDB239FA95310651B1B56FD2CFE53C87352EBD996E33256160404CE9302A08066801E786A2F86E181F949966F492A85B58EAA4A6A8CB3697551BB236E87CC7BF8EC1347871C91E15437E8F266BF1EA5EB271FDCF374D8B47DF8BCE89E1FAD61C2A088CB4036B359CB72A294973FEDCCF0C340AFFD14B64F041165581ACA34147C1C75617047058F7ED7D603E032508094FA73E8B9153DA3BF255D2CBBC5DF301BA8F74D198BEBCE86040FC1D2927C7657414490D802F482F3EBF2DE35EE149A1A6DE8D16891FBFBA02A18AFE59F9D6F149744E5F0D559B10203010001"
       },
       "issuerUniqueID": null,
       "subjectUniqueID": null,
       "extensions": [
         {
           "_type": "Extension",
           "extnID": {
             "_type": "OBJECT IDENTIFIER",
             "oid": "2.5.29.35",
             "components": [
               2,
               5,
               29,
               35
             ],
             "name": "id-x509-ce-authorityKeyIdentifier"
           },
           "critical": false,
           "extnValue": "301680141ADB994AB58BE57A0CC9B900E7851E1A43C08660",
           "_extnValue_choice": "ext-AuthorityKeyIdentifier",
           "_extnValue": {
             "_type": "AuthorityKeyIdentifier",
             "keyIdentifier": "1ADB994AB58BE57A0CC9B900E7851E1A43C08660",
             "authorityCertIssuer": null,
             "authorityCertSerialNumber": null
           }
         },
         {
           "_type": "Extension",
           "extnID": {
             "_type": "OBJECT IDENTIFIER",
             "oid": "2.5.29.32",
             "components": [
               2,
               5,
               29,
               32
             ],
             "name": "id-x509-ce-certificatePolicies"
           },
           "critical": false,
           "extnValue": "303930370604551D2000302F302D06082B060105050702011621687474703A2F2F7777772E73742E636F6D2F54504D2F7265706F7369746F72792F",
           "_extnValue_choice": "ext-CertificatePolicies",
           "_extnValue": [
             {
               "_type": "PolicyInformation",
               "policyIdentifier": {
                 "_type": "OBJECT IDENTIFIER",
                 "oid": "2.5.29.32.0",
                 "components": [
                   2,
                   5,
                   29,
                   32,
                   0
                 ],
                 "name": "id-x509-ce-certificatePolicies-anyPolicy"
               },
               "policyQualifiers": [
                 {
                   "_type": "PolicyQualifierInfo",
                   "policyQualifierId": {
                     "_type": "OBJECT IDENTIFIER",
                     "oid": "1.3.6.1.5.5.7.2.1",
                     "components": [
                       1,
                       3,
                       6,
                       1,
                       5,
                       5,
                       7,
                       2,
                       1
                     ],
                     "name": "id-pkix-qt-cps"
                   },
                   "qualifier": "1621687474703A2F2F7777772E73742E636F6D2F54504D2F7265706F7369746F72792F"
                 }
               ]
             }
           ]
         },
         {
           "_type": "Extension",
           "extnID": {
             "_type": "OBJECT IDENTIFIER",
             "oid": "2.5.29.17",
             "components": [
               2,
               5,
               29,
               17
             ],
             "name": "id-x509-ce-subjectAltName"
           },
           "critical": true,
           "extnValue": "304DA44B304931163014060567810502010C0B69643A353335343444323031173015060567810502020C0C53543333485450484148433031163014060567810502030C0B69643A3030343930303038",
           "_extnValue_choice": "ext-SubjectAltName",
           "_extnValue": [
             {
               "_choice": "directoryName",
               "value": {
                 "_choice": "rdnSequence",
                 "value": [
                   [
                     {
                       "_type": "AttributeTypeAndValue",
                       "type": {
                         "_type": "OBJECT IDENTIFIER",
                         "oid": "2.23.133.2.1",
                         "components": [
                           2,
                           23,
                           133,
                           2,
                           1
                         ],
                         "name": "tcg-at-tpmManufacturer"
                       },
                       "value": {
                         "_choice": "utf8String",
                         "value": "id:53544D20"
                       }
                     }
                   ],
                   [
                     {
                       "_type": "AttributeTypeAndValue",
                       "type": {
                         "_type": "OBJECT IDENTIFIER",
                         "oid": "2.23.133.2.2",
                         "components": [
                           2,
                           23,
                           133,
                           2,
                           2
                         ],
                         "name": "tcg-at-tpmModel"
                       },
                       "value": {
                         "_choice": "utf8String",
                         "value": "ST33HTPHAHC0"
                       }
                     }
                   ],
                   [
                     {
                       "_type": "AttributeTypeAndValue",
                       "type": {
                         "_type": "OBJECT IDENTIFIER",
                         "oid": "2.23.133.2.3",
                         "components": [
                           2,
                           23,
                           133,
                           2,
                           3
                         ],
                         "name": "tcg-at-tpmVersion"
                       },
                       "value": {
                         "_choice": "utf8String",
                         "value": "id:00490008"
                       }
                     }
                   ]
                 ]
               }
             }
           ]
         },
         {
           "_type": "Extension",
           "extnID": {
             "_type": "OBJECT IDENTIFIER",
             "oid": "2.5.29.9",
             "components": [
               2,
               5,
               29,
               9
             ],
             "name": "id-x509-ce-subjectDirectoryAttributes"
           },
           "critical": false,
           "extnValue": "305E301706056781050210310E300C0C03322E300201000202008A304306056781050212313A30380201000101FFA0030A0101A1030A0100A2030A0100A310300E1603332E310A01040A01020101FFA40F300D16053134302D320A0102010100",
           "_extnValue_choice": "ext-SubjectDirectoryAttributes",
           "_extnValue": [
             {
               "_type": "AttributeSet",
               "type": {
                 "_type": "OBJECT IDENTIFIER",
                 "oid": "2.23.133.2.16",
                 "components": [
                   2,
                   23,
                   133,
                   2,
                   16
                 ],
                 "name": "tcg-at-tpmSpecification"
               },
               "values": [
                 "300C0C03322E300201000202008A"
               ],
               "_values_choice": "at-TPMSpecification",
               "_values": [
                 {
                   "_type": "TPMSpecification",
                   "family": "2.0",
                   "level": 0,
                   "revision": 138
                 }
               ]
             },
             {
               "_type": "AttributeSet",
               "type": {
                 "_type": "OBJECT IDENTIFIER",
                 "oid": "2.23.133.2.18",
                 "components": [
                   2,
                   23,
                   133,
                   2,
                   18
                 ],
                 "name": "tcg-at-tpmSecurityAssertions"
               },
               "values": [
                 "30380201000101FFA0030A0101A1030A0100A2030A0100A310300E1603332E310A01040A01020101FFA40F300D16053134302D320A0102010100"
               ],
               "_values_choice": "at-TPMSecurityAssertions",
               "_values": [
                 {
                   "_type": "TPMSecurityAssertions",
                   "version": "0",
                   "fieldUpgradable": true,
                   "ekGenerationType": "655617",
                   "ekGenerationLocation": "655616",
                   "ekCertificateGenerationLocation": "655616",
                   "ccInfo": {
                     "_type": "CommonCriteriaMeasures",
                     "version": "3.1",
                     "assurancelevel": "4",
                     "evaluationStatus": "2",
                     "plus": true,
                     "strengthOfFunction": null,
                     "profileOid": null,
                     "profileUri": null,
                     "targetOid": null,
                     "targetUri": null
                   },
                   "fipsLevel": {
                     "_type": "FIPSLevel",
                     "version": "140-2",
                     "level": "2",
                     "plus": false
                   },
                   "iso9000Certified": false,
                   "iso9000Uri": null
                 }
               ]
             }
           ]
         },
         {
           "_type": "Extension",
           "extnID": {
             "_type": "OBJECT IDENTIFIER",
             "oid": "2.5.29.15",
             "components": [
               2,
               5,
               29,
               15
             ],
             "name": "id-x509-ce-keyUsage"
           },
           "critical": true,
           "extnValue": "03020520",
           "_extnValue_choice": "ext-KeyUsage",
           "_extnValue": [
             "keyEncipherment"
           ]
         },
         {
           "_type": "Extension",
           "extnID": {
             "_type": "OBJECT IDENTIFIER",
             "oid": "2.5.29.19",
             "components": [
               2,
               5,
               29,
               19
             ],
             "name": "id-x509-ce-basicConstraints"
           },
           "critical": true,
           "extnValue": "3000",
           "_extnValue_choice": "ext-BasicConstraints",
           "_extnValue": {
             "_type": "BasicConstraints",
             "cA": false,
             "pathLenConstraint": null
           }
         },
         {
           "_type": "Extension",
           "extnID": {
             "_type": "OBJECT IDENTIFIER",
             "oid": "2.5.29.37",
             "components": [
               2,
               5,
               29,
               37
             ],
             "name": "id-x509-ce-extKeyUsage"
           },
           "critical": false,
           "extnValue": "300706056781050801",
           "_extnValue_choice": "ext-ExtKeyUsage",
           "_extnValue": [
             {
               "_type": "OBJECT IDENTIFIER",
               "oid": "2.23.133.8.1",
               "components": [
                 2,
                 23,
                 133,
                 8,
                 1
               ],
               "name": "tcg-kp-EKCertificate"
             }
           ]
         },
         {
           "_type": "Extension",
           "extnID": {
             "_type": "OBJECT IDENTIFIER",
             "oid": "1.3.6.1.5.5.7.1.1",
             "components": [
               1,
               3,
               6,
               1,
               5,
               5,
               7,
               1,
               1
             ],
             "name": "id-pkix-pe-authorityInfoAccess"
           },
           "critical": false,
           "extnValue": "303C303A06082B06010505073002862E687474703A2F2F7365637572652E676C6F62616C7369676E2E636F6D2F73746D74706D656B696E7430352E637274",
           "_extnValue_choice": "ext-AuthorityInfoAccess",
           "_extnValue": [
             {
               "_type": "AccessDescription",
               "accessMethod": {
                 "_type": "OBJECT IDENTIFIER",
                 "oid": "1.3.6.1.5.5.7.48.2",
                 "components": [
                   1,
                   3,
                   6,
                   1,
                   5,
                   5,
                   7,
                   48,
                   2
                 ],
                 "name": "id-pkix-ad-caIssuers"
               },
               "accessLocation": {
                 "_choice": "uniformResourceIdentifier",
                 "value": "http://secure.globalsign.com/stmtpmekint05.crt"
               }
             }
           ]
         }
       ]
     },
     "signatureAlgorithm": {
       "_type": "AlgorithmIdentifier",
       "algorithm": {
         "_type": "OBJECT IDENTIFIER",
         "oid": "1.2.840.113549.1.1.11",
         "components": [
           1,
           2,
           840,
           113549,
           1,
           1,
           11
         ],
         "name": "id-pkcs1-sha256WithRSAEncryption"
       },
       "parameters": "0500"
     },
     "signatureValue": "2048:3D4C381E5B4F1BCBE09C63D52F1F04570CAEA142FD9CD942043B11F8E3BDCF50007AE16CF8869013041E92CDD3280BA4B51FBBD40582ED750219E261A695095674855AACEB520ADAFF9E7E908480A39CDCF900462D9171960FFE55D3AC49E8C981341BBD2EFBCC252A4C18A4F3B7C84CCE42CE70A208C84D2630A7ABFBE72D6271E75B9FF1C971D20EB3DBD763F1E04D834EAA692D2E4001BBF4730A3E3FDA9711AE386524D91C63BE0E516D00D5C6141FCCF6C539F3518E180049865BE16B69CAE1F8CB7FDC474B38F7EE56CBE7D8A89D9BA99B65D5265AEF32AA62426B10E6D75BB8677EC44F755BBC2806FD2B4E04BDF5D44259DBEAA42B6F563DF7AA7506"
   }
   ```

   (Notice that OID names look a bit weird.  For reasons that may have been
   lost to time and may no longer be relevant, these OIDs are defined with
   slightly different names in the ASN.1 modules in Heimdal's source tree.
   We'll fix this eventually.)

 - Unconstrained integer types have a large integer representation in C that is
   not terribly useful in common cases.  Range constraints on integer types
   cause the compiler to use `int32_t`, `int64_t`, `uint32_t`, and/or
   `uint64_t`.

 - The Heimdal ASN.1 compiler currently handles a large subset of X.680, and
   (in a branch) a small subset of X.681, X.682, and X.683, which manifests as
   automatic handling of all open types contained in `SET`/`SEQUENCE` types
   that are parameterized with information object sets.  This allows all open
   types in PKIX certificates, for example, to get decoded automatically no
   matter how deeply nested.  We use a TCG EK certificate that has eight
   certificate extensions, including subject alternative names and subject
   directory attributes where the attribute values are not string types, and
   all of these things get decoded automatically.

 - The template backend dedups templates to save space.  This is an O(N^2) kind
   of feature that we need to make optional, but it works.  When we implement
   JER this will have the side-effect of printing the wrong type names in some
   cases because two or more types have the same templates and get deduped.

...

## Limitations

 - `asn1_print`'s JSON support is not X.697 (JER) compatible.

 - Control over C types generated is very limited, mainly only for integer
   types.

 - When using the template backend, `SET { .. }` types are currently not sorted
   by tag as they should be, but if the module author sorts them by hand then
   DER will be produced.

 - `BMPString` is not supported.

 - IA5String is not properly supported -- it's essentially treated as a
   `UTF8String` with a different tag.  This is true of all the string types.

 - Only types can be imported at this time.  Without some rototilling we likely
   will not be able to import anything other than types, values, and object
   sets.

 - Only simple value syntax is supported.  Structured value syntax is not
   supported.

 - ...

## Usage

See the manual page `asn1_compile.1`:

```
ASN1_COMPILE(1)       HEIMDAL General Commands Manual          ASN1_COMPILE(1)

NAME
     asn1_compile — compile ASN.1 modules

SYNOPSIS
     asn1_compile [--template] [--prefix-enum] [--enum-prefix=PREFIX]
                  [--encode-rfc1510-bit-string] [--decode-dce-ber]
                  [--support-ber] [--preserve-binary=TYPE-NAME]
                  [--sequence=TYPE-NAME] [--one-code-file] [--gen-name=NAME]
                  [--option-file=FILE] [--original-order] [--no-parse-units]
                  [--type-file=C-HEADER-FILE] [--version] [--help]
                  [FILE.asn1 [NAME]]

DESCRIPTION
     asn1_compile Compiles an ASN.1 module into C source code and header
     files.

     Options supported:

     --template
             Use the “template” backend instead of the “codegen” backend
             (which is the default backend).  The template backend generates
             “templates” which are akin to bytecode, and which are interpreted
             at run-time.  The codegen backend generates C code for all func‐
             tions directly, with no template interpretation.  The template
             backend scales better than the codegen backend because as we add
             support for more encoding rules the templates stay mostly the
             same, thus scaling linearly with size of module.  Whereas the
             codegen backend scales linear with the product of module size and
             number of encoding rules supported.  More importantly, currently
             only the template backend supports automatic decoding of open
             types via X.681/X.682/X.683 annotations.

     --prefix-enum
             This option should be removed because ENUMERATED types should
             always have their labels prefixed.

     --enum-prefix=PREFIX
             This option should be removed because ENUMERATED types should
             always have their labels prefixed.

     --encode-rfc1510-bit-string
             Use RFC1510, non-standard handling of “BIT STRING” types.

     --decode-dce-ber
     --support-ber

     --preserve-binary=TYPE-NAME
             Generate ‘_save’ fields in structs to preserve the original
             encoding of some sub-value.  This is useful for cryptographic
             applications to avoid having to re-encode values to check signa‐
             tures, etc.

     --sequence=TYPE-NAME
             Generate add/remove functions for ‘SET OF’ and ‘SEQUENCE OF’
             types.

     --one-code-file
             Generate a single source code file.  Otherwise a separate code
             file will be generated for every type.

     --gen-name=NAME
             Use NAME to form the names of the files generated.

     --option-file=FILE
             Take additional command-line options from FILE.

     --original-order
             Attempt to preserve the original order of type definition in the
             ASN.1 module.  By default the compiler generates types in a topo‐
             logical sort order.

     --no-parse-units
             Do not generate to-int / from-int functions for enumeration
             types.

     --type-file=C-HEADER-FILE
             Generate an include of the named header file that might be needed
             for common type defintions.

     --version

     --help

HEIMDAL                        February 22, 2021                       HEIMDAL

```

## Implementation

...

## Futures

 - Add JER support so we can convert between JER and DER?

 - Add XDR support?

 - Add OER support?

 - Add NDR support?

 - Perhaps third parties will contribute more control over generate types?

## Moving From C

 - Generate and output a JSON representation of the compiled ASN.1 module.

 - Code codegen/templategen backends in jq or Haskell or whatever.

 - Code template interpreters in some host language.

 - Eventually rewrite the compiler itself in Rust or whatever.
