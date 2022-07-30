

package schema

import (
	"time"
)

func paymentInstruct(doc *Document) (paymentInstruct, error) {
	output := paymentInstruct{
		// AdrLine https://www.iso20022.org/sites/default/files/documents/D7/Pain013%20Pain%20014%20Request%20to%20Pay%20Real%20Time%20Payment%20Sep2018_v0.1.pdf
		AdrLine:                doc.AdrLine.Max70Text,                                     // "<AdrLine>"
		// Agt - Agent (Identification of a person, an organisation or a financial institution.)
		Agt:                    doc.Agt.BranchAndFinancialInstitutionIdentification5,      // "<Agt>"
		// Assgne Identification of a person, an organisation or a financial institution.
		Assgne:                 doc.Assgne.Party35Choice,                                  // "<Assgne>"
		// Assgnr - Assgnr (Unique and unambiguous identification of a financial institution or a branch of a financial institution.)
		Assgnr:                 doc.Assgnr.Party7Choice,                                   // "<Assgnr>"
		// BICFI Valid BICs for financial institutions are registered and published by the ISO 9362 Registration Authority in the ISO directory of BICs, and consist of eight (8) or eleven (11) contiguous characters
		BICFI:                  doc.BICFI.BankIdentificationCode,                          // "<BICFI>"
		// BizMsgIdr AppHdr/BizMsgIdr
		// BizMsgIdr https://www.ecb.europa.eu/paym/target/t2s/profuse/shared/pdf/business_application_header.pdf?602ad4edf0248c35bd3be9b2983ed098
		BizMsgIdr:              doc.BizMsgIdr.BusinessMessageIdentifier,                   // "<BizMsgIdr>"
		// BldgNb The address line needs to have tags as <StrtNm> and <BldgNb> in the XML file generated using SEPA_CT_03 layout format. Only Building Tag is Fixed as <StrtNm> is not a mandatory, SEPA uses ISO XML standards and in that this tag is not mandatory.
		// BldgNb https://www.ing.nl/media/ING_enkelvoudig_wereld_pain001_ibp_ING_tcm162-45636.pdf
		BldgNb:                 doc.BldgNb.Max16Text,                                      // "<BldgNb>"
		// CanonicalizationMethod https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.xml.signedinfo.canonicalizationmethod?view=dotnet-plat-ext-6.0
		// CanonicalizationMethod https://docs.oracle.com/javase/8/docs/api/javax/xml/crypto/dsig/CanonicalizationMethod.html
		// CanonicalizationMethod https://docs.oracle.com/en/java/javase/13/docs/api/java.xml.crypto/javax/xml/crypto/dsig/CanonicalizationMethod.html
		// CanonicalizationMethod https://www.di-mgt.com.au/xmldsig-c14n.html
		CanonicalizationMethod: doc.CanonicalizationMethod.CanonicalizationMethod,         // "<CanonicalizationMethod>"
		// CdtrAgt https://wiki.xmldation.com/Support/CE/CdtrAgt
		CdtrAgt:                doc.CdtrAgt.BranchAndFinancialInstitutionIdentification4,  // "<CdtrAgt>"
		// CdtTrfTxInf https://wiki.xmldation.com/Support/RBS/CT_Rules/SEPA_Rules/CdtTrfTxInf%2F%2FCdtrAgt%2F%2FBIC
		CdtTrfTxInf:            doc.CdtTrfTxInf.CreditTransferTransactionInformation11,    // "<CdtTrfTxInf>"
		// ChrgBr https://wiki.xmldation.com/support/nordea/chrgbr
		ChrgBr:                 doc.ChrgBr.ChargeBearerType1Code,                          // "<ChrgBr>"
		// ChrgsInf https://www.ecb.europa.eu/paym/groups/shared/docs/9e140-2020-09-22-tccg-rtgs-and-clm-business-validation-rules-udfs-interim-version-q2-2020.pdf
		// ChrgsInf https://www.citibank.com/tts/sa/flippingbook/2021/ISO-20022-Citi-Mini-Series-and-Reference-Guide-Part-2/12/
		ChrgsInf:               doc.ChrgsInf.ChargesInformation5,                          // "<ChrgsInf>"
		// Conf - Confirmation /Document/RsltnOfInvstgtn/Sts/Conf
		// Conf - Specifies the result of an investigation, as published in an external investigation execution confirmation code set.
        // Conf - External code sets can be downloaded from www.iso20022.org.
		Conf:                   doc.Conf.ExternalInvestigationExecutionConfirmation1Co,    // "<Conf>"
		// CreDt - Creation Date Time
		// CreDt /Document/RsltnOfInvstgtn/CrrctnTx/IntrBk/GrpHdr/CreDtTm
		CreDt:                  doc.CreDt.ISONormalisedDateTime,                           // "<CreDt>"
		// CreDtTm https://wiki.xmldation.com/Support/Nordea/CreDtTm 
		// CreDtTm CreationDateTime
		// CreDtTm https://docs.oracle.com/cd/E16582_01/doc.91/e15104/fields_sepa_pay_file_appx.htm
		CreDtTm:                doc.CreDtTm.ISODateTime,                                   // "<CreDtTm>"
		// Cretr Creator
		// Cretr Document/RsltnOfInvstgtn/RslvdCase/Cretr 
		Cretr:                  doc.Cretr.Party35Choice,                                   // "<Cretr>"
		// Ctry Country
		// Ctry CountryCode
		// Ctry /Document/RsltnOfInvstgtn/RslvdCase/Cretr/Pty/PstlAdr/Ctr
		Ctry:                   doc.Ctry.CountryCode,                                      // "<Ctry>"
		// CxlRsnInf https://wiki.xmldation.com/Support/Nordea/CancellationRequest/Cancellation_Request_%2F%2F_CancellationReason2Code
		// CxlRsnInf https://www.ecb.europa.eu/paym/target/tips/profuse/shared/pdf/TIPS_UDFS_v4.0.1_210528_rev.pdf
		// CxlRsnInf CancellationReason2Code
		// CxlRsnInf /OrgnlGrpInf/CxlRsnInf/CxlRsn/Cd
		// CxlRsnInf /TxInf/CxlRsnInf/CxlRsn/Cd
		CxlRsnInf:              doc.CxlRsnInf.CancellationReasonInformation3,              // "<CxlRsnInf>"
		// Dbtr https://wiki.xmldation.com/Support/FK/Dbtr
		// Dbtr Dbtr/Nm
		// Dbtr https://docs.oracle.com/cd/E16582_01/doc.91/e15104/fields_sepa_pay_file_appx.htm
		Dbtr:                   doc.Dbtr.PartyIdentification32,                            // "<Dbtr>"
		// DbtrAgt - DbtrAgt and CdtrAgt BIC 
		// DbtrAgt https://wiki.xmldation.com/Support/FK/DbtrAgt
		// DbtrAgt - DbtrAgt/FinInstnId/BIC
		DbtrAgt:                doc.DbtrAgt.BranchAndFinancialInstitutionIdentification4,  // "<DbtrAgt>"
		// EndToEndId https://wiki.xmldation.com/Support/ISO20022/General_Rules/EndToEndId
		// EndToEndId https://www.jam-software.com/sepa-transfer/end-to-end-id.shtml
		// EndToEndId https://answers.sap.com/questions/12267089/element-endtoendid-not-filled-in-xml-payment-file.html
		// EndToEndId https://answers.sap.com/questions/10275743/dmee-%E2%80%93-endtoendid-with-paymantorder.html
		EndToEndId:             doc.EndToEndId.EndToEndId,                                 // "<EndToEndId>"
		// Envlp - Technical component that contains the validated supplementary data information. This technical envelope allows to segregate the supplementary data information from any other information.
		// Envlp - SupplementaryDataEnvelope1
		// Envlp - /Document/RsltnOfInvstgtn/SplmtryData/Envlp
		Envlp:                  doc.Envlp.SupplementaryDataEnvelope1,                      // "<Envlp>"
		// FIId https://www.iso.org/iso-22000-food-safety-management.html
		// FIId https://www.qyriel.com/FullCatalogue/ISO_HEAD/out/ProtocolReport/xsd_head/head.001.001.01.xsd.html
		// FIId Financial Institution Identification
		// FIId AppHdr/Fr [Choice]
		FIId:                   doc.FIId.FinancialInstitutionIdentification,               // "<FIId>"
		// FinInstnId EPC limits the usage of Debtor Agent (DbtrAgt) and Creditor Agent CdtrAgt to allow only BIC and nothing else.
		// FinInstnId https://wiki.xmldation.com/Support/EPC/FinInstnId
		// FinInstnId https://wiki.xmldation.com/Support/RBS/CT_Rules/Global_Rules/CdtTrfTxInf%2F%2FCdtrAgt%2F%2FFinInstnId%2F%2FPstlAdr
		// FinInstnId CdtTrfTxInf/CdtrAgt/FinInstnId/PstlAdr Following fields from CreditorAgent / FinancialInstitutionIdentification / PostalAddress / Department '<CdtrAgt><FinInstnId><PstlAdr><Dept>'
		FinInstnId:             doc.FinInstnId.FinancialInstitutionIdentification7,        // "<FinInstnId>"
		// FIToFICstmrCdtTrf element name="FIToFICstmrCdtTrf"
		// FIToFICstmrCdtTrf https://www2.swift.com/knowledgecentre/rest/v1/publications/stdsmx_pcs_mdrs/4.0/SR2020_MX_PaymentsClearingAndSettlement_MDR1_Standards.pdf?logDownload=true
		// FIToFICstmrCdtTrf FIToFICstmrCdtTrf/GrpHdr/MsgId
		// FIToFICstmrCdtTrf FIToFICstmrCdtTrf +GrpHdr ++SttlmInf +++SttlmAcct
		FIToFICstmrCdtTrf:      doc.FIToFICstmrCdtTrf.FIToFICustomerCreditTransferV02,     // "<FIToFICstmrCdtTrf>"
		// FIToFIPmtCxlReq element name="FIToFIPmtCxlReq"
		// FIToFIPmtCxlReq - Document.FIToFIPmtCxlReq.Undrlyg.TxInf.OrgnlIntrBkSttlmAmt
		// FIToFIPmtCxlReq - /Document/FIToFIPmtCxlReq
		FIToFIPmtCxlReq:        doc.FIToFIPmtCxlReq.FIToFIPaymentCancellationRequestV01,   // "<FIToFIPmtCxlReq>"
		// FIToFIPmtStsRpt element name="FIToFIPmtStsRpt"
		// <FIToFIPmtStsRpt>
		// <GrpHdr xmlns="">-- i need this xmlns tag out
		//  <MsgId />
		// </GrpHdr>
	    //  </FIToFIPmtStsRpt>
	    // </Document>
		// FIToFIPmtStsRpt - FIToFIPaymentStatusReportV03
		FIToFIPmtStsRpt:        doc.FIToFIPmtStsRpt.FIToFIPaymentStatusReportV03,          // "<FIToFIPmtStsRpt>"
		// Fr - From - The sending MessagingEndpoint that has created this Business Message for the receiving MessagingEndpoint that will process this Business Message. Note the sending MessagingEndpoint might be different from the sending address potentially contained in the transport header (as defined in the transport layer). 
		Fr:                     doc.Fr.Party9Choice,                                       // "<Fr>"
		// GrpHdr - <CstmrCdtTrfInitn> <GrpHdr>
		// GrpHdr - GroupHeader90
		// GrpHdr Set of characteristics shared by all individual transactions included in the message
		GrpHdr:                 doc.GrpHdr.GroupHeader33,                                  // "<GrpHdr>"
		// Id - Identification
		// /Document/PmtRtr/GrpHdr/SttlmInf/SttlmAcct/Id/IBAN
		Id:                     doc.Id.Max35Text,                                          // "<Id>"
		// </InstgAgt>; <InstdAgt>.
		InstdAgt:               doc.InstdAgt.BranchAndFinancialInstitutionIdentification4, // "<InstdAgt>"
		// InstdAmt /Document/UblToApply/Undrlyg/Initn/OrgnlTxRef/Amt/InstdAmt
		// InstdAmt https://wiki.xmldation.com/General_Information/ISO_20022/Difference_between_InstdAmt_and_EqvtAmt
		//    <EqvtAmt>
		// <Amt Ccy="EUR">100</Amt>
		// <CcyOfTrf>USD</CcyOfTrf>
	    // </EqvtAmt>
		InstdAmt:               doc.InstdAmt.ActiveOrHistoricCurrencyAndAmount,            // "<InstdAmt>"
		// InstgAgt https://www.swift.com/swift-resource/248686/download
		// InstgAgt https://community.oracle.com/tech/developers/discussion/4327286/ora-00904-error-outer-join-19c
		// InstgAgt https://www.nacha.org/content/iso-20022-ach-mapping-guide
		// InstgAgt https://www.iso20022.org/sites/default/files/documents/D7/ISO20022_RTPG_pacs00800106_July_2017_v1_1.pdf
		InstgAgt:               doc.InstgAgt.BranchAndFinancialInstitutionIdentification4, // "<InstgAgt>"
		// InstrId https://wiki.xmldation.com/Support/ISO20022/General_Rules/InstrId
		// InstrId https://www.mathworks.com/help/instrument/instrid.html
		// InstrId https://wiki.xmldation.com/Support/Sampo/InstrId
		// InstrId https://docs.oracle.com/cd/E16582_01/doc.91/e15104/fields_sepa_pay_file_appx.htm#EOAEL01692
		InstrId:                doc.InstrId.InstructionIdentification,                     // "<InstrId>"
		// IntrBkSttlmAmt https://www.ecb.europa.eu/paym/groups/shared/docs/75299-tips-_cg_2017-09-28_presentation_udfs.pdf
		// IntrBkSttlmAmt https://wiki.xmldation.com/General_Information/ISO_20022/Difference_between_InstdAmt_and_EqvtAmt
		// IntrBkSttlmAmt https://www.iotafinance.com/en/SWIFT-ISO15022-Message-type-MT202-COV.html
		// IntrBkSttlmAmt https://www.bnymellon.com/content/dam/bnymellon/documents/pdf/iso-20022/Module%201_September%202020_Demystifying%20ISO20022.pdf
		IntrBkSttlmAmt:         doc.IntrBkSttlmAmt.ActiveOrHistoricCurrencyAndAmount,      // "<IntrBkSttlmAmt>"
		// IntrBkSttlmDt https://www.citibank.com/tts/sa/flippingbook/2021/ISO-20022-Citi-Mini-Series-and-Reference-Guide-Part-2/10/
		// IntrBkSttlmDt https://www.citibank.com/tts/sa/flippingbook/2021/ISO-20022-Citi-Mini-Series-and-Reference-Guide-Part-2/26/
		// IntrBkSttlmDt https://www.paymentstandards.ch/dam/mapping-rules_pacs008_esr.pdf
		// IntrBkSttlmDt https://www.payments.ca/sites/default/files/part_a_of_5_fitofi_customer_credit_transfers.pdf
		IntrBkSttlmDt:          doc.IntrBkSttlmDt.InterbankSettlementDate,                 // "<IntrBkSttlmDt>"
		// Issr /Document/UblToApply/Undrlyg/Initn/OrgnlTxRef/CdtrSchmeId/PstlAdr/AdrTp/Prtry/Issr
		// Issr Entity that assigns the identification
		Issr:                   doc.Issr.Issuer,                                           // "<Issr>"
		// Justfn /Document/UblToApply/Justfn
		// Justfn UnableToApplyJustification3Choice
		// Justfn Specifies the details of missing or incorrect information or the complete set of available information.
		Justfn:                 doc.Justfn.CaseForwardingNotification3Code,                // "<Justfn>"
		// KeyInfo KeyInfo is an optional element that enables the recipient(s) to obtain the key needed to validate the signature.
		// KeyInfo in XML signature
		KeyInfo:                doc.KeyInfo.KeyInfo,                                       // "<KeyInfo>"
		// Mod RequestedModification8
		// Mod /Document/ReqToModfyPmt/Mod
		// Mod Provide further details on the requested modifications of the underlying payment instruction.
		Mod:                    doc.Mod.RequestedModification7,                            // "<Mod>"
		// MsgDefIdr AppHdr/MsgDefIdr
		// MsgDefIdr MessageDefinitionIdentifier
		MsgDefIdr:              doc.MsgDefIdr.MessageDefinitionIdentifier,                 // "<MsgDefIdr>"
		// MsgId https://wiki.xmldation.com/Support/Nordea/MsgId
		// MsgId /GrpHdr/MsgId
		MsgId:                  doc.MsgId.MessageIdentification,                           // "<MsgId>"
		// MssngOrIncrrctInf /Document/UblToApply/Justfn/MssngOrIncrrctInf
		// MssngOrIncrrctInf MissingOrIncorrectInformation
		// MssngOrIncrrctInf urn:iso:std:iso:20022:tech:xsd:camt.026.001.03 MssngOrIncrrctInf
		MssngOrIncrrctInf:      doc.MssngOrIncrrctInf.MissingOrIncorrectInformation3,      // "<MssngOrIncrrctInf>"
		// NbOfTxs https://wiki.xmldation.com/Support/RBS/DD_Rules/Global_Rules/NbOfTxs
		// NbOfTxs https://support.oracle.com/knowledge/Oracle%20E-Business%20Suite/1571592_1.html
		// NbOfTxs https://docs.oracle.com/cd/E16582_01/doc.91/e15104/fields_sepa_pay_file_appx.htm#EOAEL01692
		// NbOfTxs https://wiki.xmldation.com/Support/ISO20022/General_Rules/NbOfTxs
		NbOfTxs:                doc.NbOfTxs.Max15NumericText,                              // "<NbOfTxs>"
		// NtfctnOfCaseAssgnmt NotificationOfCaseAssignmentV03
		// NtfctnOfCaseAssgnmt - /Document/NtfctnOfCaseAssgnmt
		// NtfctnOfCaseAssgnmt - /Document/NtfctnOfCaseAssgnmt/Hdr
		NtfctnOfCaseAssgnmt:    doc.NtfctnOfCaseAssgnmt.NotificationOfCaseAssignmentV05,   // "<NtfctnOfCaseAssgnmt>"
		// OrgnlCreDtTm https://wiki.xmldation.com/@api/deki/files/394/=Payment_Standards_proposal_Customer_to_Bank23042013_ver1_1.pdf
		// OrgnlCreDtTm <OrgnlCreDtTm>2011-11-25T11:40:58</OrgnlCreDtTm>
		OrgnlCreDtTm:           doc.OrgnlCreDtTm.ISODateTime,                              // "<OrgnlCreDtTm>"
		// OrgnlEndToEndId https://wiki.xmldation.com/Support/ISO20022/General_Rules/EndToEndId
		// OrgnlEndToEndId https://paymentcomponents.atlassian.net/wiki/spaces/AH/pages/479428560/Sample+SEPA+messages+for+Testing
		// OrgnlEndToEndId https://answers.sap.com/questions/10275743/dmee-%E2%80%93-endtoendid-with-paymantorder.html
		// OrgnlEndToEndId https://blogs.sap.com/2021/07/30/pain.002-payment-rejections-processing-via-rfebka00/
		// OrgnlEndToEndId https://docs.crbcos.com/unicorncrb/docs/unicorn-output-files
		OrgnlEndToEndId:        doc.OrgnlEndToEndId.OriginalEndToEndIdentification,        // "<OrgnlEndToEndId>"
		// OrgnlGrpInf https://www.payments.ca/sites/default/files/part_c_of_5_payment_return.pdf
		// OrgnlGrpInf https://wiki.xmldation.com/Support/Nordea/CancellationRequest/Cancellation_Request_%2f%2f_CancellationReason2Code
		// OrgnlGrpInf https://www.iso20022.org/sites/default/files/documents/D7/Pacs004%20Real%20Time%20Payment%20Sep2018_v0.1.pdf
		// OrgnlGrpInf https://www.nacha.org/content/iso-20022-ach-mapping-guide
		// OrgnlGrpInf https://www.iso20022.org/sites/default/files/documents/D7/ISO20022_RTPG_pacs00200108_July_2017_v1_1.pdf
		OrgnlGrpInf:            doc.OrgnlGrpInf.OriginalGroupInformation3,                 // "<OrgnlGrpInf>"
		// OrgnlGrpInfAndCxl UnderlyingTransaction16
		// OrgnlGrpInfAndCxl Identifies the underlying (group of) transaction(s) to which the investigation applies. 
		// OrgnlGrpInfAndCxl Undrlyg/OrgnlGrpInfAndCxl /OrgnlMsgNmId Undrlyg/OrgnlGrpInfAndCxl
		// OrgnlGrpInfAndCxl <xs:element maxOccurs="1" minOccurs="0" name="OrgnlGrpInfAndCxl" type="OriginalGroupInformation23"/>
		// OrgnlGrpInfAndCxl Document/FIToFIPmtCxlReq/Undrlyg/OrgnlGrpInfAndCxl
		// OrgnlGrpInfAndCxl Original Group Information And Cancellation
		OrgnlGrpInfAndCxl:      doc.OrgnlGrpInfAndCxl.OriginalGroupInformation23,          // "<OrgnlGrpInfAndCxl>"
		// OrgnlGrpInfAndSts /Document/FIToFIPmtStsRpt/OrgnlGrpInfAndSts
		// OrgnlGrpInfAndSts OriginalGroupHeader17
		// OrgnlGrpInfAndSts Provides details on the original group, to which the message refers.
		OrgnlGrpInfAndSts:      doc.OrgnlGrpInfAndSts.OriginalGroupInformation20,          // "<OrgnlGrpInfAndSts>"
		// OrgnlInstdAmt /Document/UblToApply/Undrlyg/Initn/OrgnlInstdAmt
		// OrgnlInstdAmt ActiveOrHistoricCurrencyAndAmount
		// OrgnlInstdAmt /Document/UblToApply/Undrlyg/Initn/OrgnlInstdAmt
		OrgnlInstdAmt:          doc.OrgnlInstdAmt.OriginalInstructedAmount,                // "<OrgnlInstdAmt>"
		// OrgnlInstrId https://www.iso20022.org/sites/default/files/documents/D7/Pacs004%20Real%20Time%20Payment%20Sep2018_v0.1.pdf
		// OrgnlInstrId https://paymentcomponents.atlassian.net/wiki/spaces/AH/pages/479428560/Sample+SEPA+messages+for+Testing
		// OrgnlInstrId https://stackoverflow.com/questions/65199828/parsing-xml-in-c-sharp-with-xsd-file
		// OrgnlInstrId https://github.com/FasterXML/jackson-dataformat-xml/issues/217
		OrgnlInstrId:           doc.OrgnlInstrId.OriginalInstructionIdentification,        // "<OrgnlInstrId>"
		// OrgnlIntrBkSttlmAmt Document/FIToFIPmtCxlReq/Undrlyg/TxInf/OrgnlIntrBkSttlmAmt
		// OrgnlIntrBkSttlmAmt https://www.bundesbank.de/resource/blob/752410/4d247d818d3ba9ca1ba8cfa5f6eb7814/mL/technische-spezifikationen-sdd-anhang-112018-data.pdf
		OrgnlIntrBkSttlmAmt:    doc.OrgnlIntrBkSttlmAmt.ActiveOrHistoricCurrencyAndAmount, // "<OrgnlIntrBkSttlmAmt>"
		// OrgnlMsgId  </GrpHdr> <OrgnlGrpInfAndSts> <OrgnlMsgId>
		// OrgnlMsgId <OrgnlMsgId> Tag Value In Camt.056
		// OrgnlMsgId https://support.oracle.com/knowledge/Oracle%20Financial%20Services%20Software/2772227_1.html
		OrgnlMsgId:             doc.OrgnlMsgId.OriginalMessageIdentification,              // "<OrgnlMsgId>"
		// OrgnlMsgNmId https://www.nordea.com/en/doc/pain-002-examples-status-report.pdf
		// OrgnlMsgNmId https://danskeci.com/-/media/pdf/danskeci-com/sepa/formats/sepa-direct-debit-acknowledgement.pdf?rev=bd219e7ba36241f29f0bb11910c85747&hash=D03F9BBA732E4FA0F38B97ACFF850FD8
		// OrgnlMsgNmId  /Document/FIToFIPmtCxlReq/Undrlyg/OrgnlGrpInfAndCxl/OrgnlMsgNmId
		OrgnlMsgNmId:           doc.OrgnlMsgNmId.OriginalMessageNameIdentification,        // "<OrgnlMsgNmId>"
		// OrgnlTxId OriginalTransactionIdentification
		// OrgnlTxId /Document/FIToFIPmtCxlReq/Undrlyg/TxInf/OrgnlTxId
		// OrgnlTxId Unique identification, as assigned by the original first instructing agent, to unambiguously identify the transaction.
		OrgnlTxId:              doc.OrgnlTxId.OriginalTransactionIdentification,           // "<OrgnlTxId>"
		// OrgnlTxRef OriginalTransactionReference
		// OrgnlTxRef /Document/FIToFIPmtCxlReq/Undrlyg/TxInf/OrgnlTxRef
		// OrgnlTxRef Key elements used to refer the original transaction.
		OrgnlTxRef:             doc.OrgnlTxRef.OriginalTransactionReference13,             // "<OrgnlTxRef>"
		// Orgtr PartyIdentification135
		// Orgtr /Document/FIToFIPmtCxlReq/Undrlyg/OrgnlGrpInfAndCxl/CxlRsnInf/Orgtr
		Orgtr:                  doc.Orgtr.PartyIdentification32,                           // "<Orgtr>"
		// PlcAndNm /Document/FIToFIPmtCxlReq/Undrlyg/TxInf/SplmtryData/PlcAndNm
		// PlcAndNm PlcAndNm
		// PlcAndNm Unambiguous reference to the location where the supplementary data must be inserted in the message instance.
		PlcAndNm:               doc.PlcAndNm.PlcAndNm,                                     // "<PlcAndNm>"
		// PmtTpInf Document/FIToFIPmtCxlReq/Undrlyg/TxInf/OrgnlTxRef/PmtTpInf 
		// PmtTpInf PmtTpInf
		PmtTpInf:               doc.PmtTpInf.PaymentTypeInformation21,                     // "<PmtTpInf>"
		// PstCd /Document/FIToFICstmrCdtTrf/CdtTrfTxInf/ChrgsInf/Agt/FinInstnId/PstlAdr/PstCd
		// PstCd PostCode
		PstCd:                  doc.PstCd.Max16Text,                                       // "<PstCd>"
		// PstlAdr /Document/FIToFICstmrCdtTrf/CdtTrfTxInf/ChrgsInf/Agt/FinInstnId/PstlAdr/TwnNm
		// PstlAdr TownName
		PstlAdr:                doc.PstlAdr.PostalAddress6,                                // "<PstlAdr>"
		// ReqToModfyPmt RequestToModifyPaymentV06
		// ReqToModfyPmt /Document/ReqToModfyPmt
		ReqToModfyPmt:          doc.ReqToModfyPmt.RequestToModifyPaymentV05,               // "<ReqToModfyPmt>"
		// RsltnOfInvstgtn ResolutionOfInvestigationV09
		// RsltnOfInvstgtn /Document/RsltnOfInvstgtn
		RsltnOfInvstgtn:        doc.RsltnOfInvstgtn.ResolutionOfInvestigationV08,          // "<RsltnOfInvstgtn>"
		// RtrdInstdAmt /Document/PmtRtr/TxInf/RtrdInstdAmt
		// RtrdInstdAmt ReturnedInstructedAmount
		RtrdInstdAmt:           doc.RtrdInstdAmt.ActiveOrHistoricCurrencyAndAmount,        // "<RtrdInstdAmt>"
		// RtrdIntrBkSttlmAmt Returned Interbank Settlement Amount
		// RtrdIntrBkSttlmAmt ReturnedInterbankSettlementAmount
		// RtrdIntrBkSttlmAmt /Document/PmtRtr/TxInf/RtrdIntrBkSttlmAmt
		RtrdIntrBkSttlmAmt:     doc.RtrdIntrBkSttlmAmt.ActiveCurrencyAndAmount,            // "<RtrdIntrBkSttlmAmt>"
		// RtrId /Document/PmtRtr/TxInf/RtrId
		// RtrId ReturnIdentification
		// RtrId Unique identification, as assigned by an instructing party for an instructed party, to unambiguously identify the returned transaction.
		RtrId:                  doc.RtrId.Max35Text,                                       // "<RtrId>"
		// RtrRsnInf PaymentReturnReason1
		// RtrRsnInf ReturnReasonInformation
		// RtrRsnInf /Document/PmtRtr/TxInf/RtrRsnInf
		RtrRsnInf:              doc.RtrRsnInf.ReturnReasonInformation9,                    // "<RtrRsnInf>"
		// Signature - Sign XML Documents
		// Signature - Digital Signatures
		Signature:              doc.Signature.Signature,                                   // "<Signature>"
		// SignatureMethod name of the algorithm used for signature generation
		// The SignatureMethod property uses a string Uniform Resource Identifier (URI) to represents the <SignatureMethod> element of an XML digital signature.
		SignatureMethod:        doc.SignatureMethod.SignatureMethod,                       // "<SignatureMethod>"
		// SplmtryData SupplementaryData
		// SplmtryData Document/FIToFIPmtStsRpt/TxInfAndSts/SplmtryData
		// SplmtryData Additional information that cannot be captured in the structured elements and/or any other specific block.
		SplmtryData:            doc.SplmtryData.SupplementaryData1,                        // "<SplmtryData>"
		// StrtNm StreetName
		// StrtNm /Document/FIToFIPmtStsRpt/GrpHdr/InstgAgt/FinInstnId/PstlAdr/StrtNm
		StrtNm:                 doc.StrtNm.Max70Text,                                      // "<StrtNm>"
		// SttlmAcct SettlementAccount
		// SttlmAcct /Document/FIToFIPmtStsRpt/TxInfAndSts/OrgnlTxRef/SttlmInf/SttlmAcct
		SttlmAcct:              doc.SttlmAcct.CashAccount16,                               // "<SttlmAcct>"
		// SttlmInf SettlementInformation
		// SttlmInf /Document/FIToFIPmtStsRpt/TxInfAndSts/OrgnlTxRef/SttlmInf
		SttlmInf:               doc.SttlmInf.SettlementInformation13,                      // "<SttlmInf>"
		// SttlmMtd SettlementMethod
		// SttlmMtd /Document/FIToFIPmtStsRpt/TxInfAndSts/OrgnlTxRef/SttlmInf/SttlmMtd
		SttlmMtd:               doc.SttlmMtd.SettlementMethod1Code,                        // "<SttlmMtd>"
		// SvcLvl /Document/FIToFIPmtStsRpt/TxInfAndSts/OrgnlTxRef/PmtTpInf/SvcLvl
		// SvcLvl ServiceLevel
		// SvcLvl ServiceLevel8Choice
		SvcLvl:                 doc.SvcLvl.ServiceLevel8Choice,                            // "<SvcLvl>"
		// To AppHdr/To
		To:                     doc.To.Party9Choice,                                       // "<To>"
		// TwnNm TownName
		// /Document/FIToFIPmtStsRpt/TxInfAndSts/OrgnlTxRef/MndtRltdInf/AmdmntInfDtls/OrgnlCdtrSchmeId/PstlAdr/TwnNm
		TwnNm:                  doc.TwnNm.Max35Text,                                       // "<TwnNm>"
		// TxId FIToFICstmrCdtTrf TransactionIdentification
		// TxId /Document/FIToFICstmrCdtTrf/CdtTrfTxInf/PmtId/TxId
		// TxId Unique identification, as assigned by the first instructing agent, to unambiguously identify the transaction that is passed on, unchanged, throughout the entire interbank chain.
		TxId:                   doc.TxId.TransactionIdentification,                        // "<TxId>"
		// TxInfAndSts /Document/FIToFIPmtStsRpt/TxInfAndSts
		// TxInfAndSts PaymentTransaction91
		TxInfAndSts:            doc.TxInfAndSts.PaymentTransactionInformation26,           // "<TxInfAndSts>"
		// TxSts ExternalPaymentTransactionStatus1Code
		// TxSts /Document/FIToFIPmtStsRpt/TxInfAndSts/TxSts
		// TxSts ExternalPaymentTransactionStatus1Code
		TxSts:                  doc.TxSts.TransactionIndividualStatus3Code,                // "<TxSts>"
		// UblToApply /Document/UblToApply
		// UblToApply UnableToApplyV07
		// UblToApply The UnableToApply message is sent by a case creator or a case assigner to a case assignee. This message is used to initiate an investigation of a payment instruction that cannot be executed or reconciled.
		UblToApply:             doc.UblToApply.UnableToApplyV07,                           // "<UblToApply>"
		// UltmtCdtr /Document/FIToFIPmtStsRpt/TxInfAndSts/OrgnlTxRef/UltmtCdtr/Pty
		// UltmtCdtr PartyIdentification125
		// UltmtCdtr Document/FIToFICstmrCdtTrf/CdtTrfTxInf/UltmtCdtr
		UltmtCdtr:              doc.UltmtCdtr.PartyIdentification32,                       // "<UltmtCdtr>"
		// Undrlyg UnderlyingTransaction5Choice
		// Undrlyg /Document/UblToApply/Undrlyg
		// Undrlyg Provides details of the underlying transaction, on which the investigation is processed.
		Undrlyg:                doc.Undrlyg.UnderlyingTransaction4Choice,                  // "<Undrlyg>"
		// X509Data - Represents an <X509Data> subelement of an XMLDSIG or XML Encryption
		// An X509Data element within KeyInfo contains one or more identifiers of keys or X509 certificates (or certificates' identifiers or a revocation list).
		X509Data:               doc.X509Data.KeyInfoX509Data,                              // "<X509Data>"
		// XchgRate ExchangeRate
		// XchgRate /Document/FIToFICstmrCdtTrf/CdtTrfTxInf/XchgRate
		// XchgRate Factor used to convert an amount from one currency into another. This reflects the price at which one currency was bought with another currency.
		XchgRate:               doc.XchgRate.BaseOneRate,                                  // "<XchgRate>"
	}
	
// Document ...
type Document *Document

// AccountIdentification4Choice ...
type AccountIdentification4Choice struct {
	IBAN string                         `xml:"IBAN"`
	Othr *GenericAccountIdentification1 `xml:"Othr"`
}

// AccountSchemeName1Choice ...
type AccountSchemeName1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// ActiveCurrencyAndAmountSimpleType ...
type ActiveCurrencyAndAmountSimpleType float64

// ActiveCurrencyAndAmount ...
type ActiveCurrencyAndAmount struct {
	CcyAttr string  `xml:"Ccy,attr"`
	Value   float64 `xml:",chardata"`
}

// ActiveCurrencyCode ...
type ActiveCurrencyCode string

// ActiveOrHistoricCurrencyAndAmountSimpleType ...
type ActiveOrHistoricCurrencyAndAmountSimpleType float64

// ActiveOrHistoricCurrencyAndAmount ...
type ActiveOrHistoricCurrencyAndAmount struct {
	CcyAttr string  `xml:"Ccy,attr"`
	Value   float64 `xml:",chardata"`
}

// ActiveOrHistoricCurrencyCode ...
type ActiveOrHistoricCurrencyCode string

// AddressType2Code ...
type AddressType2Code string

// AnyBICIdentifier ...
type AnyBICIdentifier string

// BICIdentifier ...
type BICIdentifier string

// BatchBookingIndicator ...
type BatchBookingIndicator bool

// BranchAndFinancialInstitutionIdentification4 ...
type BranchAndFinancialInstitutionIdentification4 struct {
	FinInstnId *FinancialInstitutionIdentification7 `xml:"FinInstnId"`
	BrnchId    *BranchData2                         `xml:"BrnchId"`
}

// BranchData2 ...
type BranchData2 struct {
	Id      string          `xml:"Id"`
	Nm      string          `xml:"Nm"`
	PstlAdr *PostalAddress6 `xml:"PstlAdr"`
}

// CashAccount16 ...
type CashAccount16 struct {
	Id  *AccountIdentification4Choice `xml:"Id"`
	Tp  *CashAccountType2             `xml:"Tp"`
	Ccy string                        `xml:"Ccy"`
	Nm  string                        `xml:"Nm"`
}

// CashAccountType2 ...
type CashAccountType2 struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// CashAccountType4Code ...
type CashAccountType4Code string

// ClearingChannel2Code ...
type ClearingChannel2Code string

// ClearingSystemIdentification2Choice ...
type ClearingSystemIdentification2Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// ClearingSystemIdentification3Choice ...
type ClearingSystemIdentification3Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// ClearingSystemMemberIdentification2 ...
type ClearingSystemMemberIdentification2 struct {
	ClrSysId *ClearingSystemIdentification2Choice `xml:"ClrSysId"`
	MmbId    string                               `xml:"MmbId"`
}

// ContactDetails2 ...
type ContactDetails2 struct {
	NmPrfx   string `xml:"NmPrfx"`
	Nm       string `xml:"Nm"`
	PhneNb   string `xml:"PhneNb"`
	MobNb    string `xml:"MobNb"`
	FaxNb    string `xml:"FaxNb"`
	EmailAdr string `xml:"EmailAdr"`
	Othr     string `xml:"Othr"`
}

// CountryCode ...
type CountryCode string

// CreditDebitCode ...
type CreditDebitCode string

// CreditTransferTransactionInformation12 ...
type CreditTransferTransactionInformation12 struct {
	UltmtDbtr        *PartyIdentification32                        `xml:"UltmtDbtr"`
	InitgPty         *PartyIdentification32                        `xml:"InitgPty"`
	Dbtr             *PartyIdentification32                        `xml:"Dbtr"`
	DbtrAcct         *CashAccount16                                `xml:"DbtrAcct"`
	DbtrAgt          *BranchAndFinancialInstitutionIdentification4 `xml:"DbtrAgt"`
	DbtrAgtAcct      *CashAccount16                                `xml:"DbtrAgtAcct"`
	PrvsInstgAgt     *BranchAndFinancialInstitutionIdentification4 `xml:"PrvsInstgAgt"`
	PrvsInstgAgtAcct *CashAccount16                                `xml:"PrvsInstgAgtAcct"`
	IntrmyAgt1       *BranchAndFinancialInstitutionIdentification4 `xml:"IntrmyAgt1"`
	IntrmyAgt1Acct   *CashAccount16                                `xml:"IntrmyAgt1Acct"`
	IntrmyAgt2       *BranchAndFinancialInstitutionIdentification4 `xml:"IntrmyAgt2"`
	IntrmyAgt2Acct   *CashAccount16                                `xml:"IntrmyAgt2Acct"`
	IntrmyAgt3       *BranchAndFinancialInstitutionIdentification4 `xml:"IntrmyAgt3"`
	IntrmyAgt3Acct   *CashAccount16                                `xml:"IntrmyAgt3Acct"`
	CdtrAgt          *BranchAndFinancialInstitutionIdentification4 `xml:"CdtrAgt"`
	CdtrAgtAcct      *CashAccount16                                `xml:"CdtrAgtAcct"`
	Cdtr             *PartyIdentification32                        `xml:"Cdtr"`
	CdtrAcct         *CashAccount16                                `xml:"CdtrAcct"`
	UltmtCdtr        *PartyIdentification32                        `xml:"UltmtCdtr"`
	RmtInf           *RemittanceInformation5                       `xml:"RmtInf"`
	InstdAmt         *ActiveOrHistoricCurrencyAndAmount            `xml:"InstdAmt"`
}

// CreditTransferTransactionInformation13 ...
type CreditTransferTransactionInformation13 struct {
	PmtId              *PaymentIdentification3                       `xml:"PmtId"`
	PmtTpInf           *PaymentTypeInformation23                     `xml:"PmtTpInf"`
	IntrBkSttlmAmt     *ActiveCurrencyAndAmount                      `xml:"IntrBkSttlmAmt"`
	IntrBkSttlmDt      string                                        `xml:"IntrBkSttlmDt"`
	SttlmPrty          string                                        `xml:"SttlmPrty"`
	SttlmTmIndctn      *SettlementDateTimeIndication1                `xml:"SttlmTmIndctn"`
	SttlmTmReq         *SettlementTimeRequest2                       `xml:"SttlmTmReq"`
	PrvsInstgAgt       *BranchAndFinancialInstitutionIdentification4 `xml:"PrvsInstgAgt"`
	PrvsInstgAgtAcct   *CashAccount16                                `xml:"PrvsInstgAgtAcct"`
	InstgAgt           *BranchAndFinancialInstitutionIdentification4 `xml:"InstgAgt"`
	InstdAgt           *BranchAndFinancialInstitutionIdentification4 `xml:"InstdAgt"`
	IntrmyAgt1         *BranchAndFinancialInstitutionIdentification4 `xml:"IntrmyAgt1"`
	IntrmyAgt1Acct     *CashAccount16                                `xml:"IntrmyAgt1Acct"`
	IntrmyAgt2         *BranchAndFinancialInstitutionIdentification4 `xml:"IntrmyAgt2"`
	IntrmyAgt2Acct     *CashAccount16                                `xml:"IntrmyAgt2Acct"`
	IntrmyAgt3         *BranchAndFinancialInstitutionIdentification4 `xml:"IntrmyAgt3"`
	IntrmyAgt3Acct     *CashAccount16                                `xml:"IntrmyAgt3Acct"`
	UltmtDbtr          *BranchAndFinancialInstitutionIdentification4 `xml:"UltmtDbtr"`
	Dbtr               *BranchAndFinancialInstitutionIdentification4 `xml:"Dbtr"`
	DbtrAcct           *CashAccount16                                `xml:"DbtrAcct"`
	DbtrAgt            *BranchAndFinancialInstitutionIdentification4 `xml:"DbtrAgt"`
	DbtrAgtAcct        *CashAccount16                                `xml:"DbtrAgtAcct"`
	CdtrAgt            *BranchAndFinancialInstitutionIdentification4 `xml:"CdtrAgt"`
	CdtrAgtAcct        *CashAccount16                                `xml:"CdtrAgtAcct"`
	Cdtr               *BranchAndFinancialInstitutionIdentification4 `xml:"Cdtr"`
	CdtrAcct           *CashAccount16                                `xml:"CdtrAcct"`
	UltmtCdtr          *BranchAndFinancialInstitutionIdentification4 `xml:"UltmtCdtr"`
	InstrForCdtrAgt    []*InstructionForCreditorAgent2               `xml:"InstrForCdtrAgt"`
	InstrForNxtAgt     []*InstructionForNextAgent1                   `xml:"InstrForNxtAgt"`
	RmtInf             *RemittanceInformation2                       `xml:"RmtInf"`
	UndrlygCstmrCdtTrf *CreditTransferTransactionInformation12       `xml:"UndrlygCstmrCdtTrf"`
}

// CreditorReferenceInformation2 ...
type CreditorReferenceInformation2 struct {
	Tp  *CreditorReferenceType2 `xml:"Tp"`
	Ref string                  `xml:"Ref"`
}

// CreditorReferenceType1Choice ...
type CreditorReferenceType1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// CreditorReferenceType2 ...
type CreditorReferenceType2 struct {
	CdOrPrtry *CreditorReferenceType1Choice `xml:"CdOrPrtry"`
	Issr      string                        `xml:"Issr"`
}

// DateAndPlaceOfBirth ...
type DateAndPlaceOfBirth struct {
	BirthDt     string `xml:"BirthDt"`
	PrvcOfBirth string `xml:"PrvcOfBirth"`
	CityOfBirth string `xml:"CityOfBirth"`
	CtryOfBirth string `xml:"CtryOfBirth"`
}

// DecimalNumber ...
type DecimalNumber float64

// DocumentAdjustment1 ...
type DocumentAdjustment1 struct {
	Amt       *ActiveOrHistoricCurrencyAndAmount `xml:"Amt"`
	CdtDbtInd string                             `xml:"CdtDbtInd"`
	Rsn       string                             `xml:"Rsn"`
	AddtlInf  string                             `xml:"AddtlInf"`
}

// DocumentType3Code ...
type DocumentType3Code string

// DocumentType5Code ...
type DocumentType5Code string

// ExternalAccountIdentification1Code ...
type ExternalAccountIdentification1Code string

// ExternalCashClearingSystem1Code ...
type ExternalCashClearingSystem1Code string

// ExternalClearingSystemIdentification1Code ...
type ExternalClearingSystemIdentification1Code string

// ExternalFinancialInstitutionIdentification1Code ...
type ExternalFinancialInstitutionIdentification1Code string

// ExternalLocalInstrument1Code ...
type ExternalLocalInstrument1Code string

// ExternalOrganisationIdentification1Code ...
type ExternalOrganisationIdentification1Code string

// ExternalPersonIdentification1Code ...
type ExternalPersonIdentification1Code string

// ExternalServiceLevel1Code ...
type ExternalServiceLevel1Code string

// FinancialIdentificationSchemeName1Choice ...
type FinancialIdentificationSchemeName1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// FinancialInstitutionCreditTransferV02 ...
type FinancialInstitutionCreditTransferV02 struct {
	GrpHdr      *GroupHeader35                            `xml:"GrpHdr"`
	CdtTrfTxInf []*CreditTransferTransactionInformation13 `xml:"CdtTrfTxInf"`
}

// FinancialInstitutionIdentification7 ...
type FinancialInstitutionIdentification7 struct {
	BIC         string                               `xml:"BIC"`
	ClrSysMmbId *ClearingSystemMemberIdentification2 `xml:"ClrSysMmbId"`
	Nm          string                               `xml:"Nm"`
	PstlAdr     *PostalAddress6                      `xml:"PstlAdr"`
	Othr        *GenericFinancialIdentification1     `xml:"Othr"`
}

// GenericAccountIdentification1 ...
type GenericAccountIdentification1 struct {
	Id      string                    `xml:"Id"`
	SchmeNm *AccountSchemeName1Choice `xml:"SchmeNm"`
	Issr    string                    `xml:"Issr"`
}

// GenericFinancialIdentification1 ...
type GenericFinancialIdentification1 struct {
	Id      string                                    `xml:"Id"`
	SchmeNm *FinancialIdentificationSchemeName1Choice `xml:"SchmeNm"`
	Issr    string                                    `xml:"Issr"`
}

// GenericOrganisationIdentification1 ...
type GenericOrganisationIdentification1 struct {
	Id      string                                       `xml:"Id"`
	SchmeNm *OrganisationIdentificationSchemeName1Choice `xml:"SchmeNm"`
	Issr    string                                       `xml:"Issr"`
}

// GenericPersonIdentification1 ...
type GenericPersonIdentification1 struct {
	Id      string                                 `xml:"Id"`
	SchmeNm *PersonIdentificationSchemeName1Choice `xml:"SchmeNm"`
	Issr    string                                 `xml:"Issr"`
}

// GroupHeader35 ...
type GroupHeader35 struct {
	MsgId             string                                        `xml:"MsgId"`
	CreDtTm           string                                        `xml:"CreDtTm"`
	BtchBookg         bool                                          `xml:"BtchBookg"`
	NbOfTxs           string                                        `xml:"NbOfTxs"`
	CtrlSum           float64                                       `xml:"CtrlSum"`
	TtlIntrBkSttlmAmt *ActiveCurrencyAndAmount                      `xml:"TtlIntrBkSttlmAmt"`
	IntrBkSttlmDt     string                                        `xml:"IntrBkSttlmDt"`
	SttlmInf          *SettlementInformation13                      `xml:"SttlmInf"`
	PmtTpInf          *PaymentTypeInformation23                     `xml:"PmtTpInf"`
	InstgAgt          *BranchAndFinancialInstitutionIdentification4 `xml:"InstgAgt"`
	InstdAgt          *BranchAndFinancialInstitutionIdentification4 `xml:"InstdAgt"`
}

// IBAN2007Identifier ...
type IBAN2007Identifier string

// ISODate ...
type ISODate string

// ISODateTime ...
type ISODateTime string

// ISOTime ...
type ISOTime time.Time

// Instruction4Code ...
type Instruction4Code string

// Instruction5Code ...
type Instruction5Code string

// InstructionForCreditorAgent2 ...
type InstructionForCreditorAgent2 struct {
	Cd       string `xml:"Cd"`
	InstrInf string `xml:"InstrInf"`
}

// InstructionForNextAgent1 ...
type InstructionForNextAgent1 struct {
	Cd       string `xml:"Cd"`
	InstrInf string `xml:"InstrInf"`
}

// LocalInstrument2Choice ...
type LocalInstrument2Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// Max140Text ...
type Max140Text string

// Max15NumericText ...
type Max15NumericText string

// Max16Text ...
type Max16Text string

// Max2048Text ...
type Max2048Text string

// Max34Text ...
type Max34Text string

// Max35Text ...
type Max35Text string

// Max4Text ...
type Max4Text string

// Max70Text ...
type Max70Text string

// NamePrefix1Code ...
type NamePrefix1Code string

// OrganisationIdentification4 ...
type OrganisationIdentification4 struct {
	BICOrBEI string                                `xml:"BICOrBEI"`
	Othr     []*GenericOrganisationIdentification1 `xml:"Othr"`
}

// OrganisationIdentificationSchemeName1Choice ...
type OrganisationIdentificationSchemeName1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// Party6Choice ...
type Party6Choice struct {
	OrgId  *OrganisationIdentification4 `xml:"OrgId"`
	PrvtId *PersonIdentification5       `xml:"PrvtId"`
}

// PartyIdentification32 ...
type PartyIdentification32 struct {
	Nm        string           `xml:"Nm"`
	PstlAdr   *PostalAddress6  `xml:"PstlAdr"`
	Id        *Party6Choice    `xml:"Id"`
	CtryOfRes string           `xml:"CtryOfRes"`
	CtctDtls  *ContactDetails2 `xml:"CtctDtls"`
}

// PaymentIdentification3 ...
type PaymentIdentification3 struct {
	InstrId    string `xml:"InstrId"`
	EndToEndId string `xml:"EndToEndId"`
	TxId       string `xml:"TxId"`
	ClrSysRef  string `xml:"ClrSysRef"`
}

// PaymentTypeInformation23 ...
type PaymentTypeInformation23 struct {
	InstrPrty string                  `xml:"InstrPrty"`
	ClrChanl  string                  `xml:"ClrChanl"`
	SvcLvl    *ServiceLevel8Choice    `xml:"SvcLvl"`
	LclInstrm *LocalInstrument2Choice `xml:"LclInstrm"`
}

// PersonIdentification5 ...
type PersonIdentification5 struct {
	DtAndPlcOfBirth *DateAndPlaceOfBirth            `xml:"DtAndPlcOfBirth"`
	Othr            []*GenericPersonIdentification1 `xml:"Othr"`
}

// PersonIdentificationSchemeName1Choice ...
type PersonIdentificationSchemeName1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// PhoneNumber ...
type PhoneNumber string

// PostalAddress6 ...
type PostalAddress6 struct {
	AdrTp       string   `xml:"AdrTp"`
	Dept        string   `xml:"Dept"`
	SubDept     string   `xml:"SubDept"`
	StrtNm      string   `xml:"StrtNm"`
	BldgNb      string   `xml:"BldgNb"`
	PstCd       string   `xml:"PstCd"`
	TwnNm       string   `xml:"TwnNm"`
	CtrySubDvsn string   `xml:"CtrySubDvsn"`
	Ctry        string   `xml:"Ctry"`
	AdrLine     []string `xml:"AdrLine"`
}

// Priority2Code ...
type Priority2Code string

// Priority3Code ...
type Priority3Code string

// ReferredDocumentInformation3 ...
type ReferredDocumentInformation3 struct {
	Tp     *ReferredDocumentType2 `xml:"Tp"`
	Nb     string                 `xml:"Nb"`
	RltdDt string                 `xml:"RltdDt"`
}

// ReferredDocumentType1Choice ...
type ReferredDocumentType1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// ReferredDocumentType2 ...
type ReferredDocumentType2 struct {
	CdOrPrtry *ReferredDocumentType1Choice `xml:"CdOrPrtry"`
	Issr      string                       `xml:"Issr"`
}

// RemittanceAmount1 ...
type RemittanceAmount1 struct {
	DuePyblAmt        *ActiveOrHistoricCurrencyAndAmount `xml:"DuePyblAmt"`
	DscntApldAmt      *ActiveOrHistoricCurrencyAndAmount `xml:"DscntApldAmt"`
	CdtNoteAmt        *ActiveOrHistoricCurrencyAndAmount `xml:"CdtNoteAmt"`
	TaxAmt            *ActiveOrHistoricCurrencyAndAmount `xml:"TaxAmt"`
	AdjstmntAmtAndRsn []*DocumentAdjustment1             `xml:"AdjstmntAmtAndRsn"`
	RmtdAmt           *ActiveOrHistoricCurrencyAndAmount `xml:"RmtdAmt"`
}

// RemittanceInformation2 ...
type RemittanceInformation2 struct {
	Ustrd []string `xml:"Ustrd"`
}

// RemittanceInformation5 ...
type RemittanceInformation5 struct {
	Ustrd []string                            `xml:"Ustrd"`
	Strd  []*StructuredRemittanceInformation7 `xml:"Strd"`
}

// ServiceLevel8Choice ...
type ServiceLevel8Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// SettlementDateTimeIndication1 ...
type SettlementDateTimeIndication1 struct {
	DbtDtTm string `xml:"DbtDtTm"`
	CdtDtTm string `xml:"CdtDtTm"`
}

// SettlementInformation13 ...
type SettlementInformation13 struct {
	SttlmMtd             string                                        `xml:"SttlmMtd"`
	SttlmAcct            *CashAccount16                                `xml:"SttlmAcct"`
	ClrSys               *ClearingSystemIdentification3Choice          `xml:"ClrSys"`
	InstgRmbrsmntAgt     *BranchAndFinancialInstitutionIdentification4 `xml:"InstgRmbrsmntAgt"`
	InstgRmbrsmntAgtAcct *CashAccount16                                `xml:"InstgRmbrsmntAgtAcct"`
	InstdRmbrsmntAgt     *BranchAndFinancialInstitutionIdentification4 `xml:"InstdRmbrsmntAgt"`
	InstdRmbrsmntAgtAcct *CashAccount16                                `xml:"InstdRmbrsmntAgtAcct"`
	ThrdRmbrsmntAgt      *BranchAndFinancialInstitutionIdentification4 `xml:"ThrdRmbrsmntAgt"`
	ThrdRmbrsmntAgtAcct  *CashAccount16                                `xml:"ThrdRmbrsmntAgtAcct"`
}

// SettlementMethod1Code ...
type SettlementMethod1Code string

// SettlementTimeRequest2 ...
type SettlementTimeRequest2 struct {
	CLSTm  time.Time `xml:"CLSTm"`
	TillTm time.Time `xml:"TillTm"`
	FrTm   time.Time `xml:"FrTm"`
	RjctTm time.Time `xml:"RjctTm"`
}

// StructuredRemittanceInformation7 ...
type StructuredRemittanceInformation7 struct {
	RfrdDocInf  []*ReferredDocumentInformation3 `xml:"RfrdDocInf"`
	RfrdDocAmt  *RemittanceAmount1              `xml:"RfrdDocAmt"`
	CdtrRefInf  *CreditorReferenceInformation2  `xml:"CdtrRefInf"`
	Invcr       *PartyIdentification32          `xml:"Invcr"`
	Invcee      *PartyIdentification32          `xml:"Invcee"`
	AddtlRmtInf []string                        `xml:"AddtlRmtInf"`
}
