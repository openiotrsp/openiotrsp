package asn1

import "github.com/damonto/euicc-go/bertlv"

var (
	tagSequence = bertlv.Universal.Constructed(16)
	tagInteger  = bertlv.Universal.Primitive(2)
	tagOctet    = bertlv.Universal.Primitive(4)
	tagNull     = bertlv.Universal.Primitive(5)
	tagUTF8     = bertlv.Universal.Primitive(12)

	tagEID          = bertlv.Application.Primitive(26) // SGP.32 Octet16, tag 5A.
	tagSignature    = bertlv.Application.Primitive(55) // SGP.32 eIM/eUICC signature, tag 5F37.
	tagEuiccPkg     = bertlv.ContextSpecific.Constructed(81)
	tagIpaEuiccData = bertlv.ContextSpecific.Constructed(82)
	tagEimAck       = bertlv.ContextSpecific.Constructed(83)
	tagDownloadTrig = bertlv.ContextSpecific.Constructed(84)

	tagTransferEimPackage = bertlv.ContextSpecific.Constructed(78)
	tagGetEimPackage      = bertlv.ContextSpecific.Constructed(79)
	tagProvideEimResult   = bertlv.ContextSpecific.Constructed(80)

	tagProfileInfoList     = bertlv.ContextSpecific.Constructed(45)
	tagProfileInfo         = bertlv.Private.Constructed(3)
	tagProfileState        = bertlv.ContextSpecific.Primitive(112)
	tagFallbackAttribute   = bertlv.ContextSpecific.Primitive(38)
	tagProfileInstall      = bertlv.ContextSpecific.Constructed(55)
	tagProfileInstallData  = bertlv.ContextSpecific.Constructed(39)
	tagProfileFinalResult  = bertlv.ContextSpecific.Constructed(2)
	tagSetDefaultDPAddress = bertlv.ContextSpecific.Constructed(101)
)
