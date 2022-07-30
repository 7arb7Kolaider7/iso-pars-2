

package schema

import (
	"encoding/xml"
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

// AccountIdentification3Choice ...
type AccountIdentification3Choice struct {
	IBAN      string                            `xml:"IBAN"`
	BBAN      string                            `xml:"BBAN"`
	UPIC      string                            `xml:"UPIC"`
	PrtryAcct *SimpleIdentificationInformation2 `xml:"PrtryAcct"`
}

// AddressType2Code ...
type AddressType2Code string

// AmountType2Choice ...
type AmountType2Choice struct {
	InstdAmt *CurrencyAndAmount `xml:"InstdAmt"`
	EqvtAmt  *EquivalentAmount  `xml:"EqvtAmt"`
}

// BBANIdentifier ...
type BBANIdentifier string

// BEIIdentifier ...
type BEIIdentifier string

// BICIdentifier ...
type BICIdentifier string

// BaseOneRate ...
type BaseOneRate float64

// BatchBookingIndicator ...
type BatchBookingIndicator bool

// BranchAndFinancialInstitutionIdentification3 ...
type BranchAndFinancialInstitutionIdentification3 struct {
	FinInstnId *FinancialInstitutionIdentification5Choice `xml:"FinInstnId"`
	BrnchId    *BranchData                                `xml:"BrnchId"`
}

// BranchData ...
type BranchData struct {
	Id      string          `xml:"Id"`
	Nm      string          `xml:"Nm"`
	PstlAdr *PostalAddress1 `xml:"PstlAdr"`
}

// CHIPSUniversalIdentifier ...
type CHIPSUniversalIdentifier string

// CashAccount7 ...
type CashAccount7 struct {
	Id  *AccountIdentification3Choice `xml:"Id"`
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

// ChargeBearerType1Code ...
type ChargeBearerType1Code string

// Cheque5 ...
type Cheque5 struct {
	ChqTp       string                       `xml:"ChqTp"`
	ChqNb       string                       `xml:"ChqNb"`
	ChqFr       *NameAndAddress3             `xml:"ChqFr"`
	DlvryMtd    *ChequeDeliveryMethod1Choice `xml:"DlvryMtd"`
	DlvrTo      *NameAndAddress3             `xml:"DlvrTo"`
	InstrPrty   string                       `xml:"InstrPrty"`
	ChqMtrtyDt  string                       `xml:"ChqMtrtyDt"`
	FrmsCd      string                       `xml:"FrmsCd"`
	MemoFld     string                       `xml:"MemoFld"`
	RgnlClrZone string                       `xml:"RgnlClrZone"`
	PrtLctn     string                       `xml:"PrtLctn"`
}

// ChequeDelivery1Code ...
type ChequeDelivery1Code string

// ChequeDeliveryMethod1Choice ...
type ChequeDeliveryMethod1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// ChequeType2Code ...
type ChequeType2Code string

// ClearingChannel2Code ...
type ClearingChannel2Code string

// ClearingSystemMemberIdentification3Choice ...
type ClearingSystemMemberIdentification3Choice struct {
	Id    string `xml:"Id"`
	Prtry string `xml:"Prtry"`
}

// CountryCode ...
type CountryCode string

// CreditTransferTransactionInformation1 ...
type CreditTransferTransactionInformation1 struct {
	PmtId           *PaymentIdentification1                       `xml:"PmtId"`
	PmtTpInf        *PaymentTypeInformation1                      `xml:"PmtTpInf"`
	Amt             *AmountType2Choice                            `xml:"Amt"`
	XchgRateInf     *ExchangeRateInformation1                     `xml:"XchgRateInf"`
	ChrgBr          string                                        `xml:"ChrgBr"`
	ChqInstr        *Cheque5                                      `xml:"ChqInstr"`
	UltmtDbtr       *PartyIdentification8                         `xml:"UltmtDbtr"`
	IntrmyAgt1      *BranchAndFinancialInstitutionIdentification3 `xml:"IntrmyAgt1"`
	IntrmyAgt1Acct  *CashAccount7                                 `xml:"IntrmyAgt1Acct"`
	IntrmyAgt2      *BranchAndFinancialInstitutionIdentification3 `xml:"IntrmyAgt2"`
	IntrmyAgt2Acct  *CashAccount7                                 `xml:"IntrmyAgt2Acct"`
	IntrmyAgt3      *BranchAndFinancialInstitutionIdentification3 `xml:"IntrmyAgt3"`
	IntrmyAgt3Acct  *CashAccount7                                 `xml:"IntrmyAgt3Acct"`
	CdtrAgt         *BranchAndFinancialInstitutionIdentification3 `xml:"CdtrAgt"`
	CdtrAgtAcct     *CashAccount7                                 `xml:"CdtrAgtAcct"`
	Cdtr            *PartyIdentification8                         `xml:"Cdtr"`
	CdtrAcct        *CashAccount7                                 `xml:"CdtrAcct"`
	UltmtCdtr       *PartyIdentification8                         `xml:"UltmtCdtr"`
	InstrForCdtrAgt []*InstructionForCreditorAgent1               `xml:"InstrForCdtrAgt"`
	InstrForDbtrAgt string                                        `xml:"InstrForDbtrAgt"`
	Purp            *Purpose1Choice                               `xml:"Purp"`
	RgltryRptg      []*RegulatoryReporting2                       `xml:"RgltryRptg"`
	Tax             *TaxInformation2                              `xml:"Tax"`
	RltdRmtInf      []*RemittanceLocation1                        `xml:"RltdRmtInf"`
	RmtInf          *RemittanceInformation1                       `xml:"RmtInf"`
}

// CreditorReferenceInformation1 ...
type CreditorReferenceInformation1 struct {
	CdtrRefTp *CreditorReferenceType1 `xml:"CdtrRefTp"`
	CdtrRef   string                  `xml:"CdtrRef"`
}

// CreditorReferenceType1 ...
type CreditorReferenceType1 struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
	Issr  string `xml:"Issr"`
}

// CurrencyAndAmountSimpleType ...
type CurrencyAndAmountSimpleType float64

// CurrencyAndAmount ...
type CurrencyAndAmount struct {
	CcyAttr string  `xml:"Ccy,attr"`
	Value   float64 `xml:",chardata"`
}

// CurrencyCode ...
type CurrencyCode string

// DateAndPlaceOfBirth ...
type DateAndPlaceOfBirth struct {
	BirthDt     string `xml:"BirthDt"`
	PrvcOfBirth string `xml:"PrvcOfBirth"`
	CityOfBirth string `xml:"CityOfBirth"`
	CtryOfBirth string `xml:"CtryOfBirth"`
}

// DecimalNumber ...
type DecimalNumber float64

// DocumentType2Code ...
type DocumentType2Code string

// DocumentType3Code ...
type DocumentType3Code string

// DunsIdentifier ...
type DunsIdentifier string

// EANGLNIdentifier ...
type EANGLNIdentifier string

// EquivalentAmount ...
type EquivalentAmount struct {
	Amt      *CurrencyAndAmount `xml:"Amt"`
	CcyOfTrf string             `xml:"CcyOfTrf"`
}

// ExchangeRateInformation1 ...
type ExchangeRateInformation1 struct {
	XchgRate float64 `xml:"XchgRate"`
	RateTp   string  `xml:"RateTp"`
	CtrctId  string  `xml:"CtrctId"`
}

// ExchangeRateType1Code ...
type ExchangeRateType1Code string

// ExternalClearingSystemMemberCode ...
type ExternalClearingSystemMemberCode string

// ExternalLocalInstrumentCode ...
type ExternalLocalInstrumentCode string

// ExternalPurposeCode ...
type ExternalPurposeCode string

// FinancialInstitutionIdentification3 ...
type FinancialInstitutionIdentification3 struct {
	BIC         string                                     `xml:"BIC"`
	ClrSysMmbId *ClearingSystemMemberIdentification3Choice `xml:"ClrSysMmbId"`
	Nm          string                                     `xml:"Nm"`
	PstlAdr     *PostalAddress1                            `xml:"PstlAdr"`
	PrtryId     *GenericIdentification3                    `xml:"PrtryId"`
}

// FinancialInstitutionIdentification5Choice ...
type FinancialInstitutionIdentification5Choice struct {
	BIC         string                                     `xml:"BIC"`
	ClrSysMmbId *ClearingSystemMemberIdentification3Choice `xml:"ClrSysMmbId"`
	NmAndAdr    *NameAndAddress7                           `xml:"NmAndAdr"`
	PrtryId     *GenericIdentification3                    `xml:"PrtryId"`
	CmbndId     *FinancialInstitutionIdentification3       `xml:"CmbndId"`
}

// GenericIdentification3 ...
type GenericIdentification3 struct {
	Id   string `xml:"Id"`
	Issr string `xml:"Issr"`
}

// GenericIdentification4 ...
type GenericIdentification4 struct {
	Id   string `xml:"Id"`
	IdTp string `xml:"IdTp"`
}

// GroupHeader1 ...
type GroupHeader1 struct {
	MsgId     string                                        `xml:"MsgId"`
	CreDtTm   string                                        `xml:"CreDtTm"`
	Authstn   []string                                      `xml:"Authstn"`
	BtchBookg bool                                          `xml:"BtchBookg"`
	NbOfTxs   string                                        `xml:"NbOfTxs"`
	CtrlSum   float64                                       `xml:"CtrlSum"`
	Grpg      string                                        `xml:"Grpg"`
	InitgPty  *PartyIdentification8                         `xml:"InitgPty"`
	FwdgAgt   *BranchAndFinancialInstitutionIdentification3 `xml:"FwdgAgt"`
}

// Grouping1Code ...
type Grouping1Code string

// IBANIdentifier ...
type IBANIdentifier string

// IBEIIdentifier ...
type IBEIIdentifier string

// ISODate ...
type ISODate string

// ISODateTime ...
type ISODateTime string

// Instruction3Code ...
type Instruction3Code string

// InstructionForCreditorAgent1 ...
type InstructionForCreditorAgent1 struct {
	Cd       string `xml:"Cd"`
	InstrInf string `xml:"InstrInf"`
}

// LocalInstrument1Choice ...
type LocalInstrument1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// Max128Text ...
type Max128Text string

// Max140Text ...
type Max140Text string

// Max15NumericText ...
type Max15NumericText string

// Max16Text ...
type Max16Text string

// Max256Text ...
type Max256Text string

// Max34Text ...
type Max34Text string

// Max35Text ...
type Max35Text string

// Max3Text ...
type Max3Text string

// Max70Text ...
type Max70Text string

// NameAndAddress3 ...
type NameAndAddress3 struct {
	Nm  string          `xml:"Nm"`
	Adr *PostalAddress1 `xml:"Adr"`
}

// NameAndAddress7 ...
type NameAndAddress7 struct {
	Nm      string          `xml:"Nm"`
	PstlAdr *PostalAddress1 `xml:"PstlAdr"`
}

// OrganisationIdentification2 ...
type OrganisationIdentification2 struct {
	BIC     string                  `xml:"BIC"`
	IBEI    string                  `xml:"IBEI"`
	BEI     string                  `xml:"BEI"`
	EANGLN  string                  `xml:"EANGLN"`
	USCHU   string                  `xml:"USCHU"`
	DUNS    string                  `xml:"DUNS"`
	BkPtyId string                  `xml:"BkPtyId"`
	TaxIdNb string                  `xml:"TaxIdNb"`
	PrtryId *GenericIdentification3 `xml:"PrtryId"`
}

// Party2Choice ...
type Party2Choice struct {
	OrgId  *OrganisationIdentification2 `xml:"OrgId"`
	PrvtId []*PersonIdentification3     `xml:"PrvtId"`
}

// PartyIdentification8 ...
type PartyIdentification8 struct {
	Nm        string          `xml:"Nm"`
	PstlAdr   *PostalAddress1 `xml:"PstlAdr"`
	Id        *Party2Choice   `xml:"Id"`
	CtryOfRes string          `xml:"CtryOfRes"`
}

// PaymentCategoryPurpose1Code ...
type PaymentCategoryPurpose1Code string

// PaymentIdentification1 ...
type PaymentIdentification1 struct {
	InstrId    string `xml:"InstrId"`
	EndToEndId string `xml:"EndToEndId"`
}

// PaymentInstructionInformation1 ...
type PaymentInstructionInformation1 struct {
	PmtInfId        string                                        `xml:"PmtInfId"`
	PmtMtd          string                                        `xml:"PmtMtd"`
	PmtTpInf        *PaymentTypeInformation1                      `xml:"PmtTpInf"`
	ReqdExctnDt     string                                        `xml:"ReqdExctnDt"`
	PoolgAdjstmntDt string                                        `xml:"PoolgAdjstmntDt"`
	Dbtr            *PartyIdentification8                         `xml:"Dbtr"`
	DbtrAcct        *CashAccount7                                 `xml:"DbtrAcct"`
	DbtrAgt         *BranchAndFinancialInstitutionIdentification3 `xml:"DbtrAgt"`
	DbtrAgtAcct     *CashAccount7                                 `xml:"DbtrAgtAcct"`
	UltmtDbtr       *PartyIdentification8                         `xml:"UltmtDbtr"`
	ChrgBr          string                                        `xml:"ChrgBr"`
	ChrgsAcct       *CashAccount7                                 `xml:"ChrgsAcct"`
	ChrgsAcctAgt    *BranchAndFinancialInstitutionIdentification3 `xml:"ChrgsAcctAgt"`
	CdtTrfTxInf     []*CreditTransferTransactionInformation1      `xml:"CdtTrfTxInf"`
}

// PaymentMethod3Code ...
type PaymentMethod3Code string

// PaymentTypeInformation1 ...
type PaymentTypeInformation1 struct {
	InstrPrty string                  `xml:"InstrPrty"`
	SvcLvl    *ServiceLevel2Choice    `xml:"SvcLvl"`
	ClrChanl  string                  `xml:"ClrChanl"`
	LclInstrm *LocalInstrument1Choice `xml:"LclInstrm"`
	CtgyPurp  string                  `xml:"CtgyPurp"`
}

// PercentageRate ...
type PercentageRate float64

// PersonIdentification3 ...
type PersonIdentification3 struct {
	DrvrsLicNb      string                  `xml:"DrvrsLicNb"`
	CstmrNb         string                  `xml:"CstmrNb"`
	SclSctyNb       string                  `xml:"SclSctyNb"`
	AlnRegnNb       string                  `xml:"AlnRegnNb"`
	PsptNb          string                  `xml:"PsptNb"`
	TaxIdNb         string                  `xml:"TaxIdNb"`
	IdntyCardNb     string                  `xml:"IdntyCardNb"`
	MplyrIdNb       string                  `xml:"MplyrIdNb"`
	DtAndPlcOfBirth *DateAndPlaceOfBirth    `xml:"DtAndPlcOfBirth"`
	OthrId          *GenericIdentification4 `xml:"OthrId"`
	Issr            string                  `xml:"Issr"`
}

// PostalAddress1 ...
type PostalAddress1 struct {
	AdrTp       string   `xml:"AdrTp"`
	AdrLine     []string `xml:"AdrLine"`
	StrtNm      string   `xml:"StrtNm"`
	BldgNb      string   `xml:"BldgNb"`
	PstCd       string   `xml:"PstCd"`
	TwnNm       string   `xml:"TwnNm"`
	CtrySubDvsn string   `xml:"CtrySubDvsn"`
	Ctry        string   `xml:"Ctry"`
}

// Priority2Code ...
type Priority2Code string

// Purpose1Choice ...
type Purpose1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// ReferredDocumentAmount1Choice ...
type ReferredDocumentAmount1Choice struct {
	DuePyblAmt   *CurrencyAndAmount `xml:"DuePyblAmt"`
	DscntApldAmt *CurrencyAndAmount `xml:"DscntApldAmt"`
	RmtdAmt      *CurrencyAndAmount `xml:"RmtdAmt"`
	CdtNoteAmt   *CurrencyAndAmount `xml:"CdtNoteAmt"`
	TaxAmt       *CurrencyAndAmount `xml:"TaxAmt"`
}

// ReferredDocumentInformation1 ...
type ReferredDocumentInformation1 struct {
	RfrdDocTp *ReferredDocumentType1 `xml:"RfrdDocTp"`
	RfrdDocNb string                 `xml:"RfrdDocNb"`
}

// ReferredDocumentType1 ...
type ReferredDocumentType1 struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
	Issr  string `xml:"Issr"`
}

// RegulatoryAuthority ...
type RegulatoryAuthority struct {
	AuthrtyNm   string `xml:"AuthrtyNm"`
	AuthrtyCtry string `xml:"AuthrtyCtry"`
}

// RegulatoryReporting2 ...
type RegulatoryReporting2 struct {
	DbtCdtRptgInd string                          `xml:"DbtCdtRptgInd"`
	Authrty       *RegulatoryAuthority            `xml:"Authrty"`
	RgltryDtls    *StructuredRegulatoryReporting2 `xml:"RgltryDtls"`
}

// RegulatoryReportingType1Code ...
type RegulatoryReportingType1Code string

// RemittanceInformation1 ...
type RemittanceInformation1 struct {
	Ustrd []string                            `xml:"Ustrd"`
	Strd  []*StructuredRemittanceInformation6 `xml:"Strd"`
}

// RemittanceLocation1 ...
type RemittanceLocation1 struct {
	RmtId             string           `xml:"RmtId"`
	RmtLctnMtd        string           `xml:"RmtLctnMtd"`
	RmtLctnElctrncAdr string           `xml:"RmtLctnElctrncAdr"`
	RmtLctnPstlAdr    *NameAndAddress3 `xml:"RmtLctnPstlAdr"`
}

// RemittanceLocationMethod1Code ...
type RemittanceLocationMethod1Code string

// ServiceLevel1Code ...
type ServiceLevel1Code string

// ServiceLevel2Choice ...
type ServiceLevel2Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// SimpleIdentificationInformation2 ...
type SimpleIdentificationInformation2 struct {
	Id string `xml:"Id"`
}

// StructuredRegulatoryReporting2 ...
type StructuredRegulatoryReporting2 struct {
	Cd  string             `xml:"Cd"`
	Amt *CurrencyAndAmount `xml:"Amt"`
	Inf string             `xml:"Inf"`
}

// StructuredRemittanceInformation6 ...
type StructuredRemittanceInformation6 struct {
	RfrdDocInf    *ReferredDocumentInformation1    `xml:"RfrdDocInf"`
	RfrdDocRltdDt string                           `xml:"RfrdDocRltdDt"`
	RfrdDocAmt    []*ReferredDocumentAmount1Choice `xml:"RfrdDocAmt"`
	CdtrRefInf    *CreditorReferenceInformation1   `xml:"CdtrRefInf"`
	Invcr         *PartyIdentification8            `xml:"Invcr"`
	Invcee        *PartyIdentification8            `xml:"Invcee"`
	AddtlRmtInf   string                           `xml:"AddtlRmtInf"`
}

// TaxDetails ...
type TaxDetails struct {
	CertId string   `xml:"CertId"`
	TaxTp  *TaxType `xml:"TaxTp"`
}

// TaxInformation2 ...
type TaxInformation2 struct {
	CdtrTaxId       string             `xml:"CdtrTaxId"`
	CdtrTaxTp       string             `xml:"CdtrTaxTp"`
	DbtrTaxId       string             `xml:"DbtrTaxId"`
	TaxRefNb        string             `xml:"TaxRefNb"`
	TtlTaxblBaseAmt *CurrencyAndAmount `xml:"TtlTaxblBaseAmt"`
	TtlTaxAmt       *CurrencyAndAmount `xml:"TtlTaxAmt"`
	TaxDt           string             `xml:"TaxDt"`
	TaxTpInf        []*TaxDetails      `xml:"TaxTpInf"`
}

// TaxType ...
type TaxType struct {
	CtgyDesc     string             `xml:"CtgyDesc"`
	Rate         float64            `xml:"Rate"`
	TaxblBaseAmt *CurrencyAndAmount `xml:"TaxblBaseAmt"`
	Amt          *CurrencyAndAmount `xml:"Amt"`
}

// UPICIdentifier ...
type UPICIdentifier string

// Pain00100102 ...
type Pain00100102 struct {
	XMLName xml.Name                          `xml:"pain.001.001.02"`
	GrpHdr  *GroupHeader1                     `xml:"GrpHdr"`
	PmtInf  []*PaymentInstructionInformation1 `xml:"PmtInf"`
}
