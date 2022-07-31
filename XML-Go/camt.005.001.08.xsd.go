package schema

// AdrLine https://www.iso20022.org/sites/default/files/documents/D7/Pain013%20Pain%20014%20Request%20to%20Pay%20Real%20Time%20Payment%20Sep2018_v0.1.pdf
// Agt - Agent (Identification of a person, an organisation or a financial institution.)
// Assgne Identification of a person, an organisation or a financial institution.
// Assgnr - Assgnr (Unique and unambiguous identification of a financial institution or a branch of a financial institution.)
// BICFI Valid BICs for financial institutions are registered and published by the ISO 9362 Registration Authority in the ISO directory of BICs, and consist of eight (8) or eleven (11) contiguous characters
// BizMsgIdr AppHdr/BizMsgIdr
// BizMsgIdr https://www.ecb.europa.eu/paym/target/t2s/profuse/shared/pdf/business_application_header.pdf?602ad4edf0248c35bd3be9b2983ed098
// BldgNb The address line needs to have tags as <StrtNm> and <BldgNb> in the XML file generated using SEPA_CT_03 layout format. Only Building Tag is Fixed as <StrtNm> is not a mandatory, SEPA uses ISO XML standards and in that this tag is not mandatory.
// BldgNb https://www.ing.nl/media/ING_enkelvoudig_wereld_pain001_ibp_ING_tcm162-45636.pdf
// CanonicalizationMethod https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.xml.signedinfo.canonicalizationmethod?view=dotnet-plat-ext-6.0
// CanonicalizationMethod https://docs.oracle.com/javase/8/docs/api/javax/xml/crypto/dsig/CanonicalizationMethod.html
// CanonicalizationMethod https://docs.oracle.com/en/java/javase/13/docs/api/java.xml.crypto/javax/xml/crypto/dsig/CanonicalizationMethod.html
// CanonicalizationMethod https://www.di-mgt.com.au/xmldsig-c14n.html
// CdtrAgt https://wiki.xmldation.com/Support/CE/CdtrAgt
// CdtTrfTxInf https://wiki.xmldation.com/Support/RBS/CT_Rules/SEPA_Rules/CdtTrfTxInf%2F%2FCdtrAgt%2F%2FBIC
// ChrgBr https://wiki.xmldation.com/support/nordea/chrgbr
// ChrgsInf https://www.ecb.europa.eu/paym/groups/shared/docs/9e140-2020-09-22-tccg-rtgs-and-clm-business-validation-rules-udfs-interim-version-q2-2020.pdf
// ChrgsInf https://www.citibank.com/tts/sa/flippingbook/2021/ISO-20022-Citi-Mini-Series-and-Reference-Guide-Part-2/12/
// Conf - Confirmation /Document/RsltnOfInvstgtn/Sts/Conf
// Conf - Specifies the result of an investigation, as published in an external investigation execution confirmation code set.
// Conf - External code sets can be downloaded from www.iso20022.org.
// CreDt - Creation Date Time
// CreDt /Document/RsltnOfInvstgtn/CrrctnTx/IntrBk/GrpHdr/CreDtTm
// CreDtTm https://wiki.xmldation.com/Support/Nordea/CreDtTm
// CreDtTm CreationDateTime
// CreDtTm https://docs.oracle.com/cd/E16582_01/doc.91/e15104/fields_sepa_pay_file_appx.htm
// Cretr Creator
// Cretr Document/RsltnOfInvstgtn/RslvdCase/Cretr
// Ctry Country
// Ctry CountryCode
// Ctry /Document/RsltnOfInvstgtn/RslvdCase/Cretr/Pty/PstlAdr/Ctr
// CxlRsnInf https://wiki.xmldation.com/Support/Nordea/CancellationRequest/Cancellation_Request_%2F%2F_CancellationReason2Code
// CxlRsnInf https://www.ecb.europa.eu/paym/target/tips/profuse/shared/pdf/TIPS_UDFS_v4.0.1_210528_rev.pdf
// CxlRsnInf CancellationReason2Code
// CxlRsnInf /OrgnlGrpInf/CxlRsnInf/CxlRsn/Cd
// CxlRsnInf /TxInf/CxlRsnInf/CxlRsn/Cd
// Dbtr https://wiki.xmldation.com/Support/FK/Dbtr
// Dbtr Dbtr/Nm
// Dbtr https://docs.oracle.com/cd/E16582_01/doc.91/e15104/fields_sepa_pay_file_appx.htm
// DbtrAgt - DbtrAgt and CdtrAgt BIC
// DbtrAgt https://wiki.xmldation.com/Support/FK/DbtrAgt
// DbtrAgt - DbtrAgt/FinInstnId/BIC
// EndToEndId https://wiki.xmldation.com/Support/ISO20022/General_Rules/EndToEndId
// EndToEndId https://www.jam-software.com/sepa-transfer/end-to-end-id.shtml
// EndToEndId https://answers.sap.com/questions/12267089/element-endtoendid-not-filled-in-xml-payment-file.html
// EndToEndId https://answers.sap.com/questions/10275743/dmee-%E2%80%93-endtoendid-with-paymantorder.html
// Envlp - Technical component that contains the validated supplementary data information. This technical envelope allows to segregate the supplementary
// data information from any other information.
// Envlp - SupplementaryDataEnvelope1
// Envlp - /Document/RsltnOfInvstgtn/SplmtryData/Envlp
// FIId https://www.iso.org/iso-22000-food-safety-management.html
// FIId https://www.qyriel.com/FullCatalogue/ISO_HEAD/out/ProtocolReport/xsd_head/head.001.001.01.xsd.html
// FIId Financial Institution Identification
// FIId AppHdr/Fr [Choice]
// FinInstnId EPC limits the usage of Debtor Agent (DbtrAgt) and Creditor Agent CdtrAgt to allow only BIC and nothing else.
// FinInstnId https://wiki.xmldation.com/Support/EPC/FinInstnId
// FinInstnId https://wiki.xmldation.com/Support/RBS/CT_Rules/Global_Rules/CdtTrfTxInf%2F%2FCdtrAgt%2F%2FFinInstnId%2F%2FPstlAdr
// FinInstnId CdtTrfTxInf/CdtrAgt/FinInstnId/PstlAdr Following fields from CreditorAgent / FinancialInstitutionIdentification / PostalAddress / Department
// FIToFICstmrCdtTrf element name="FIToFICstmrCdtTrf"
// FIToFICstmrCdtTrf https://www2.swift.com/knowledgecentre/rest/v1/publications/stdsmx_pcs_mdrs/4.0/SR2020_MX_PaymentsClearingAndSettlement_MDR1_Standards.pdf?logDownload=true
// FIToFICstmrCdtTrf FIToFICstmrCdtTrf/GrpHdr/MsgId
// FIToFICstmrCdtTrf FIToFICstmrCdtTrf +GrpHdr ++SttlmInf +++SttlmAcct
// FIToFIPmtCxlReq element name="FIToFIPmtCxlReq"
// FIToFIPmtCxlReq - Document.FIToFIPmtCxlReq.Undrlyg.TxInf.OrgnlIntrBkSttlmAmt
// FIToFIPmtCxlReq - /Document/FIToFIPmtCxlReq
// FIToFIPmtStsRpt element name="FIToFIPmtStsRpt"
// <FIToFIPmtStsRpt>
// <GrpHdr xmlns="">-- i need this xmlns tag out
//  <MsgId />
// </GrpHdr>
//  </FIToFIPmtStsRpt>
// </Document>
// FIToFIPmtStsRpt - FIToFIPaymentStatusReportV03
// Fr - From - The sending MessagingEndpoint that has created this Business Message for the receiving MessagingEndpoint that will process this Business Message. Note the sending MessagingEndpoint might be different from the sending address potentially contained in the transport header (as defined in the transport layer).
// GrpHdr - <CstmrCdtTrfInitn> <GrpHdr>
// GrpHdr - GroupHeader90
// GrpHdr Set of characteristics shared by all individual transactions included in the message
// Id - Identification
// /Document/PmtRtr/GrpHdr/SttlmInf/SttlmAcct/Id/IBAN
// </InstgAgt>; <InstdAgt>.
// InstdAmt /Document/UblToApply/Undrlyg/Initn/OrgnlTxRef/Amt/InstdAmt
// InstdAmt https://wiki.xmldation.com/General_Information/ISO_20022/Difference_between_InstdAmt_and_EqvtAmt
// <Amt Ccy="EUR">100</Amt>
// <CcyOfTrf>USD</CcyOfTrf>
// </EqvtAmt>
// InstgAgt https://www.swift.com/swift-resource/248686/download
// InstgAgt https://community.oracle.com/tech/developers/discussion/4327286/ora-00904-error-outer-join-19c
// InstgAgt https://www.nacha.org/content/iso-20022-ach-mapping-guide
// InstgAgt https://www.iso20022.org/sites/default/files/documents/D7/ISO20022_RTPG_pacs00800106_July_2017_v1_1.pdf
// InstrId https://wiki.xmldation.com/Support/ISO20022/General_Rules/InstrId
// InstrId https://www.mathworks.com/help/instrument/instrid.html
// InstrId https://wiki.xmldation.com/Support/Sampo/InstrId
// InstrId https://docs.oracle.com/cd/E16582_01/doc.91/e15104/fields_sepa_pay_file_appx.htm#EOAEL01692
// IntrBkSttlmAmt https://www.ecb.europa.eu/paym/groups/shared/docs/75299-tips-_cg_2017-09-28_presentation_udfs.pdf
// IntrBkSttlmAmt https://wiki.xmldation.com/General_Information/ISO_20022/Difference_between_InstdAmt_and_EqvtAmt
// IntrBkSttlmAmt https://www.iotafinance.com/en/SWIFT-ISO15022-Message-type-MT202-COV.html
// IntrBkSttlmAmt https://www.bnymellon.com/content/dam/bnymellon/documents/pdf/iso-20022/Module%201_September%202020_Demystifying%20ISO20022.pdf
// IntrBkSttlmDt https://www.citibank.com/tts/sa/flippingbook/2021/ISO-20022-Citi-Mini-Series-and-Reference-Guide-Part-2/10/
// IntrBkSttlmDt https://www.citibank.com/tts/sa/flippingbook/2021/ISO-20022-Citi-Mini-Series-and-Reference-Guide-Part-2/26/
// IntrBkSttlmDt https://www.paymentstandards.ch/dam/mapping-rules_pacs008_esr.pdf
// IntrBkSttlmDt https://www.payments.ca/sites/default/files/part_a_of_5_fitofi_customer_credit_transfers.pdf
// Issr /Document/UblToApply/Undrlyg/Initn/OrgnlTxRef/CdtrSchmeId/PstlAdr/AdrTp/Prtry/Issr
// Issr Entity that assigns the identification
// Justfn /Document/UblToApply/Justfn
// Justfn UnableToApplyJustification3Choice
// Justfn Specifies the details of missing or incorrect information or the complete set of available information.
// KeyInfo KeyInfo is an optional element that enables the recipient(s) to obtain the key needed to validate the signature.
// KeyInfo in XML signature
// Mod RequestedModification8
// Mod /Document/ReqToModfyPmt/Mod
// Mod Provide further details on the requested modifications of the underlying payment instruction.
// MsgDefIdr AppHdr/MsgDefIdr
// MsgDefIdr MessageDefinitionIdentifier
// MsgId https://wiki.xmldation.com/Support/Nordea/MsgId
// MsgId /GrpHdr/MsgId
// MssngOrIncrrctInf /Document/UblToApply/Justfn/MssngOrIncrrctInf
// MssngOrIncrrctInf MissingOrIncorrectInformation
// MssngOrIncrrctInf urn:iso:std:iso:20022:tech:xsd:camt.026.001.03 MssngOrIncrrctInf
// NbOfTxs https://wiki.xmldation.com/Support/RBS/DD_Rules/Global_Rules/NbOfTxs
// NbOfTxs https://support.oracle.com/knowledge/Oracle%20E-Business%20Suite/1571592_1.html
// NbOfTxs https://docs.oracle.com/cd/E16582_01/doc.91/e15104/fields_sepa_pay_file_appx.htm#EOAEL01692
// NbOfTxs https://wiki.xmldation.com/Support/ISO20022/General_Rules/NbOfTxs
// NtfctnOfCaseAssgnmt NotificationOfCaseAssignmentV03
// NtfctnOfCaseAssgnmt - /Document/NtfctnOfCaseAssgnmt
// NtfctnOfCaseAssgnmt - /Document/NtfctnOfCaseAssgnmt/Hdr
// OrgnlCreDtTm https://wiki.xmldation.com/@api/deki/files/394/=Payment_Standards_proposal_Customer_to_Bank23042013_ver1_1.pdf
// OrgnlCreDtTm <OrgnlCreDtTm>2011-11-25T11:40:58</OrgnlCreDtTm>
// OrgnlEndToEndId https://wiki.xmldation.com/Support/ISO20022/General_Rules/EndToEndId
// OrgnlEndToEndId https://paymentcomponents.atlassian.net/wiki/spaces/AH/pages/479428560/Sample+SEPA+messages+for+Testing
// OrgnlEndToEndId https://answers.sap.com/questions/10275743/dmee-%E2%80%93-endtoendid-with-paymantorder.html
// OrgnlEndToEndId https://blogs.sap.com/2021/07/30/pain.002-payment-rejections-processing-via-rfebka00/
// OrgnlEndToEndId https://docs.crbcos.com/unicorncrb/docs/unicorn-output-files
// OrgnlGrpInf https://www.payments.ca/sites/default/files/part_c_of_5_payment_return.pdf
// OrgnlGrpInf https://wiki.xmldation.com/Support/Nordea/CancellationRequest/Cancellation_Request_%2f%2f_CancellationReason2Code
// OrgnlGrpInf https://www.iso20022.org/sites/default/files/documents/D7/Pacs004%20Real%20Time%20Payment%20Sep2018_v0.1.pdf
// OrgnlGrpInf https://www.nacha.org/content/iso-20022-ach-mapping-guide
// OrgnlGrpInf https://www.iso20022.org/sites/default/files/documents/D7/ISO20022_RTPG_pacs00200108_July_2017_v1_1.pdf
// OrgnlGrpInfAndCxl UnderlyingTransaction16
// OrgnlGrpInfAndCxl Identifies the underlying (group of) transaction(s) to which the investigation applies.
// OrgnlGrpInfAndCxl Undrlyg/OrgnlGrpInfAndCxl /OrgnlMsgNmId Undrlyg/OrgnlGrpInfAndCxl
// OrgnlGrpInfAndCxl <xs:element maxOccurs="1" minOccurs="0" name="OrgnlGrpInfAndCxl" type="OriginalGroupInformation23"/>
// OrgnlGrpInfAndCxl Document/FIToFIPmtCxlReq/Undrlyg/OrgnlGrpInfAndCxl
// OrgnlGrpInfAndCxl Original Group Information And Cancellation
// OrgnlInstdAmt /Document/UblToApply/Undrlyg/Initn/OrgnlInstdAmt
// OrgnlInstdAmt ActiveOrHistoricCurrencyAndAmount
// OrgnlInstdAmt /Document/UblToApply/Undrlyg/Initn/OrgnlInstdAmt
// OrgnlInstrId https://www.iso20022.org/sites/default/files/documents/D7/Pacs004%20Real%20Time%20Payment%20Sep2018_v0.1.pdf
// OrgnlInstrId https://paymentcomponents.atlassian.net/wiki/spaces/AH/pages/479428560/Sample+SEPA+messages+for+Testing
// OrgnlInstrId https://stackoverflow.com/questions/65199828/parsing-xml-in-c-sharp-with-xsd-file
// OrgnlInstrId https://github.com/FasterXML/jackson-dataformat-xml/issues/217
// OrgnlIntrBkSttlmAmt Document/FIToFIPmtCxlReq/Undrlyg/TxInf/OrgnlIntrBkSttlmAmt
// OrgnlIntrBkSttlmAmt https://www.bundesbank.de/resource/blob/752410/4d247d818d3ba9ca1ba8cfa5f6eb7814/mL/technische-spezifikationen-sdd-anhang-112018-data.pdf
// OrgnlMsgId  </GrpHdr> <OrgnlGrpInfAndSts> <OrgnlMsgId>
// OrgnlMsgId <OrgnlMsgId> Tag Value In Camt.056
// OrgnlMsgId https://support.oracle.com/knowledge/Oracle%20Financial%20Services%20Software/2772227_1.html
// OrgnlMsgNmId https://www.nordea.com/en/doc/pain-002-examples-status-report.pdf
// OrgnlMsgNmId https://danskeci.com/-/media/pdf/danskeci-com/sepa/formats/sepa-direct-debit-acknowledgement.pdf?rev=bd219e7ba36241f29f0bb11910c85747&hash=D03F9BBA732E4FA0F38B97ACFF850FD8
// OrgnlMsgNmId  /Document/FIToFIPmtCxlReq/Undrlyg/OrgnlGrpInfAndCxl/OrgnlMsgNmId
// OrgnlTxId OriginalTransactionIdentification
// OrgnlTxId /Document/FIToFIPmtCxlReq/Undrlyg/TxInf/OrgnlTxId
// OrgnlTxId Unique identification, as assigned by the original first instructing agent, to unambiguously identify the transaction.
// OrgnlTxRef OriginalTransactionReference
// OrgnlTxRef /Document/FIToFIPmtCxlReq/Undrlyg/TxInf/OrgnlTxRef
// OrgnlTxRef Key elements used to refer the original transaction.
// Orgtr PartyIdentification135
// Orgtr /Document/FIToFIPmtCxlReq/Undrlyg/OrgnlGrpInfAndCxl/CxlRsnInf/Orgtr
// PlcAndNm /Document/FIToFIPmtCxlReq/Undrlyg/TxInf/SplmtryData/PlcAndNm
// PlcAndNm PlcAndNm
// PlcAndNm Unambiguous reference to the location where the supplementary data must be inserted in the message instance.
// PmtTpInf Document/FIToFIPmtCxlReq/Undrlyg/TxInf/OrgnlTxRef/PmtTpInf
// PmtTpInf PmtTpInf
// PstCd /Document/FIToFICstmrCdtTrf/CdtTrfTxInf/ChrgsInf/Agt/FinInstnId/PstlAdr/PstCd
// PstCd PostCode
// PstlAdr /Document/FIToFICstmrCdtTrf/CdtTrfTxInf/ChrgsInf/Agt/FinInstnId/PstlAdr/TwnNm
// PstlAdr TownName
// ReqToModfyPmt RequestToModifyPaymentV06
// ReqToModfyPmt /Document/ReqToModfyPmt
// RsltnOfInvstgtn ResolutionOfInvestigationV09
// RsltnOfInvstgtn /Document/RsltnOfInvstgtn
// RtrdInstdAmt /Document/PmtRtr/TxInf/RtrdInstdAmt
// RtrdInstdAmt ReturnedInstructedAmount
// RtrdIntrBkSttlmAmt Returned Interbank Settlement Amount
// RtrdIntrBkSttlmAmt ReturnedInterbankSettlementAmount
// RtrdIntrBkSttlmAmt /Document/PmtRtr/TxInf/RtrdIntrBkSttlmAmt
// RtrId /Document/PmtRtr/TxInf/RtrId
// RtrId ReturnIdentification
// RtrId Unique identification, as assigned by an instructing party for an instructed party, to unambiguously identify the returned transaction.
// RtrRsnInf PaymentReturnReason1
// RtrRsnInf ReturnReasonInformation
// RtrRsnInf /Document/PmtRtr/TxInf/RtrRsnInf
// Signature - Sign XML Documents
// Signature - Digital Signatures
// SignatureMethod name of the algorithm used for signature generation
// The SignatureMethod property uses a string Uniform Resource Identifier (URI) to represents the <SignatureMethod> element of an XML digital signature.
// SplmtryData SupplementaryData
// SplmtryData Document/FIToFIPmtStsRpt/TxInfAndSts/SplmtryData
// SplmtryData Additional information that cannot be captured in the structured elements and/or any other specific block.
// StrtNm StreetName
// StrtNm /Document/FIToFIPmtStsRpt/GrpHdr/InstgAgt/FinInstnId/PstlAdr/StrtNm
// SttlmAcct SettlementAccount
// SttlmAcct /Document/FIToFIPmtStsRpt/TxInfAndSts/OrgnlTxRef/SttlmInf/SttlmAcct
// SttlmInf SettlementInformation
// SttlmInf /Document/FIToFIPmtStsRpt/TxInfAndSts/OrgnlTxRef/SttlmInf
// SttlmMtd SettlementMethod
// SttlmMtd /Document/FIToFIPmtStsRpt/TxInfAndSts/OrgnlTxRef/SttlmInf/SttlmMtd
// SvcLvl /Document/FIToFIPmtStsRpt/TxInfAndSts/OrgnlTxRef/PmtTpInf/SvcLvl
// SvcLvl ServiceLevel
// SvcLvl ServiceLevel8Choice
// To AppHdr/To
// TwnNm TownName
// /Document/FIToFIPmtStsRpt/TxInfAndSts/OrgnlTxRef/MndtRltdInf/AmdmntInfDtls/OrgnlCdtrSchmeId/PstlAdr/TwnNm
// TxId FIToFICstmrCdtTrf TransactionIdentification
// TxId /Document/FIToFICstmrCdtTrf/CdtTrfTxInf/PmtId/TxId
// TxId Unique identification, as assigned by the first instructing agent, to unambiguously identify the transaction that is passed on, unchanged, throughout the entire interbank chain.
// TxInfAndSts /Document/FIToFIPmtStsRpt/TxInfAndSts
// TxInfAndSts PaymentTransaction91
// TxSts ExternalPaymentTransactionStatus1Code
// TxSts /Document/FIToFIPmtStsRpt/TxInfAndSts/TxSts
// TxSts ExternalPaymentTransactionStatus1Code
// UblToApply /Document/UblToApply
// UblToApply UnableToApplyV07
// UblToApply The UnableToApply message is sent by a case creator or a case assigner to a case assignee. This message is used to initiate an investigation of a payment instruction that cannot be executed or reconciled.
// UltmtCdtr /Document/FIToFIPmtStsRpt/TxInfAndSts/OrgnlTxRef/UltmtCdtr/Pty
// UltmtCdtr PartyIdentification125
// UltmtCdtr Document/FIToFICstmrCdtTrf/CdtTrfTxInf/UltmtCdtr
// Undrlyg UnderlyingTransaction5Choice
// Undrlyg /Document/UblToApply/Undrlyg
// Undrlyg Provides details of the underlying transaction, on which the investigation is processed.
// X509Data - Represents an <X509Data> subelement of an XMLDSIG or XML Encryption
// An X509Data element within KeyInfo contains one or more identifiers of keys or X509 certificates (or certificates' identifiers or a revocation list).
// XchgRate ExchangeRate
// XchgRate /Document/FIToFICstmrCdtTrf/CdtTrfTxInf/XchgRate
// XchgRate Factor used to convert an amount from one currency into another. This reflects the price at which one currency was bought with another currency.

// Document ...
type Document *Document

// AccountCashEntryReturnCriteria3 ...
type AccountCashEntryReturnCriteria3 struct {
	NtryRefInd  bool `xml:"NtryRefInd"`
	AcctTpInd   bool `xml:"AcctTpInd"`
	NtryAmtInd  bool `xml:"NtryAmtInd"`
	AcctCcyInd  bool `xml:"AcctCcyInd"`
	NtryStsInd  bool `xml:"NtryStsInd"`
	NtryDtInd   bool `xml:"NtryDtInd"`
	AcctSvcrInd bool `xml:"AcctSvcrInd"`
	AcctOwnrInd bool `xml:"AcctOwnrInd"`
}

// AccountIdentification4Choice ...
type AccountIdentification4Choice struct {
	IBAN string                         `xml:"IBAN"`
	Othr *GenericAccountIdentification1 `xml:"Othr"`
}

// AccountIdentificationSearchCriteria2Choice ...
type AccountIdentificationSearchCriteria2Choice struct {
	EQ     *AccountIdentification4Choice `xml:"EQ"`
	CTTxt  string                        `xml:"CTTxt"`
	NCTTxt string                        `xml:"NCTTxt"`
}

// AccountSchemeName1Choice ...
type AccountSchemeName1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// ActiveAmountRange3Choice ...
type ActiveAmountRange3Choice struct {
	ImpldCcyAndAmtRg *ImpliedCurrencyAndAmountRange1 `xml:"ImpldCcyAndAmtRg"`
	CcyAndAmtRg      *ActiveCurrencyAndAmountRange3  `xml:"CcyAndAmtRg"`
}

// ActiveCurrencyAndAmountRange3 ...
type ActiveCurrencyAndAmountRange3 struct {
	Amt       *ImpliedCurrencyAmountRange1Choice `xml:"Amt"`
	CdtDbtInd string                             `xml:"CdtDbtInd"`
	Ccy       string                             `xml:"Ccy"`
}

// ActiveCurrencyCode ...
type ActiveCurrencyCode string

// ActiveOrHistoricAmountRange2Choice ...
type ActiveOrHistoricAmountRange2Choice struct {
	ImpldCcyAndAmtRg *ImpliedCurrencyAndAmountRange1          `xml:"ImpldCcyAndAmtRg"`
	CcyAndAmtRg      *ActiveOrHistoricCurrencyAndAmountRange2 `xml:"CcyAndAmtRg"`
}

// ActiveOrHistoricCurrencyAndAmountRange2 ...
type ActiveOrHistoricCurrencyAndAmountRange2 struct {
	Amt       *ImpliedCurrencyAmountRange1Choice `xml:"Amt"`
	CdtDbtInd string                             `xml:"CdtDbtInd"`
	Ccy       string                             `xml:"Ccy"`
}

// ActiveOrHistoricCurrencyCode ...
type ActiveOrHistoricCurrencyCode string

// AddressType2Code ...
type AddressType2Code string

// AddressType3Choice ...
type AddressType3Choice struct {
	Cd    string                   `xml:"Cd"`
	Prtry *GenericIdentification30 `xml:"Prtry"`
}

// AmountRangeBoundary1 ...
type AmountRangeBoundary1 struct {
	BdryAmt float64 `xml:"BdryAmt"`
	Incl    bool    `xml:"Incl"`
}

// AnyBICDec2014Identifier ...
type AnyBICDec2014Identifier string

// BICFIDec2014Identifier ...
type BICFIDec2014Identifier string

// BranchAndFinancialInstitutionIdentification6 ...
type BranchAndFinancialInstitutionIdentification6 struct {
	FinInstnId *FinancialInstitutionIdentification18 `xml:"FinInstnId"`
	BrnchId    *BranchData3                          `xml:"BrnchId"`
}

// BranchData3 ...
type BranchData3 struct {
	Id      string           `xml:"Id"`
	LEI     string           `xml:"LEI"`
	Nm      string           `xml:"Nm"`
	PstlAdr *PostalAddress24 `xml:"PstlAdr"`
}

// CashAccountEntrySearch6 ...
type CashAccountEntrySearch6 struct {
	AcctId     []*AccountIdentificationSearchCriteria2Choice `xml:"AcctId"`
	NtryAmt    []*ActiveOrHistoricAmountRange2Choice         `xml:"NtryAmt"`
	NtryAmtCcy []string                                      `xml:"NtryAmtCcy"`
	CdtDbtInd  string                                        `xml:"CdtDbtInd"`
	NtrySts    []string                                      `xml:"NtrySts"`
	NtryDt     []*DateAndDateTimeSearch3Choice               `xml:"NtryDt"`
	AcctOwnr   *PartyIdentification135                       `xml:"AcctOwnr"`
	AcctSvcr   *BranchAndFinancialInstitutionIdentification6 `xml:"AcctSvcr"`
}

// CashPaymentStatus2Code ...
type CashPaymentStatus2Code string

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

// Contact4 ...
type Contact4 struct {
	NmPrfx    string           `xml:"NmPrfx"`
	Nm        string           `xml:"Nm"`
	PhneNb    string           `xml:"PhneNb"`
	MobNb     string           `xml:"MobNb"`
	FaxNb     string           `xml:"FaxNb"`
	EmailAdr  string           `xml:"EmailAdr"`
	EmailPurp string           `xml:"EmailPurp"`
	JobTitl   string           `xml:"JobTitl"`
	Rspnsblty string           `xml:"Rspnsblty"`
	Dept      string           `xml:"Dept"`
	Othr      []*OtherContact1 `xml:"Othr"`
	PrefrdMtd string           `xml:"PrefrdMtd"`
}

// CountryCode ...
type CountryCode string

// CreditDebitCode ...
type CreditDebitCode string

// DateAndDateTimeSearch3Choice ...
type DateAndDateTimeSearch3Choice struct {
	DtTmSch *DateTimePeriod1Choice   `xml:"DtTmSch"`
	DtSch   *DatePeriodSearch1Choice `xml:"DtSch"`
}

// DateAndPlaceOfBirth1 ...
type DateAndPlaceOfBirth1 struct {
	BirthDt     string `xml:"BirthDt"`
	PrvcOfBirth string `xml:"PrvcOfBirth"`
	CityOfBirth string `xml:"CityOfBirth"`
	CtryOfBirth string `xml:"CtryOfBirth"`
}

// DatePeriod2 ...
type DatePeriod2 struct {
	FrDt string `xml:"FrDt"`
	ToDt string `xml:"ToDt"`
}

// DatePeriodSearch1Choice ...
type DatePeriodSearch1Choice struct {
	FrDt   string       `xml:"FrDt"`
	ToDt   string       `xml:"ToDt"`
	FrToDt *DatePeriod2 `xml:"FrToDt"`
	EQDt   string       `xml:"EQDt"`
	NEQDt  string       `xml:"NEQDt"`
}

// DateTimePeriod1 ...
type DateTimePeriod1 struct {
	FrDtTm string `xml:"FrDtTm"`
	ToDtTm string `xml:"ToDtTm"`
}

// DateTimePeriod1Choice ...
type DateTimePeriod1Choice struct {
	FrDtTm string           `xml:"FrDtTm"`
	ToDtTm string           `xml:"ToDtTm"`
	DtTmRg *DateTimePeriod1 `xml:"DtTmRg"`
}

// EntryStatus1Code ...
type EntryStatus1Code string

// EntryTypeIdentifier ...
type EntryTypeIdentifier string

// Exact4AlphaNumericText ...
type Exact4AlphaNumericText string

// ExternalAccountIdentification1Code ...
type ExternalAccountIdentification1Code string

// ExternalCashClearingSystem1Code ...
type ExternalCashClearingSystem1Code string

// ExternalClearingSystemIdentification1Code ...
type ExternalClearingSystemIdentification1Code string

// ExternalEnquiryRequestType1Code ...
type ExternalEnquiryRequestType1Code string

// ExternalFinancialInstitutionIdentification1Code ...
type ExternalFinancialInstitutionIdentification1Code string

// ExternalOrganisationIdentification1Code ...
type ExternalOrganisationIdentification1Code string

// ExternalPaymentControlRequestType1Code ...
type ExternalPaymentControlRequestType1Code string

// ExternalPersonIdentification1Code ...
type ExternalPersonIdentification1Code string

// FinalStatusCode ...
type FinalStatusCode string

// FinancialIdentificationSchemeName1Choice ...
type FinancialIdentificationSchemeName1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// FinancialInstitutionIdentification18 ...
type FinancialInstitutionIdentification18 struct {
	BICFI       string                               `xml:"BICFI"`
	ClrSysMmbId *ClearingSystemMemberIdentification2 `xml:"ClrSysMmbId"`
	LEI         string                               `xml:"LEI"`
	Nm          string                               `xml:"Nm"`
	PstlAdr     *PostalAddress24                     `xml:"PstlAdr"`
	Othr        *GenericFinancialIdentification1     `xml:"Othr"`
}

// FromToAmountRange1 ...
type FromToAmountRange1 struct {
	FrAmt *AmountRangeBoundary1 `xml:"FrAmt"`
	ToAmt *AmountRangeBoundary1 `xml:"ToAmt"`
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

// GenericIdentification1 ...
type GenericIdentification1 struct {
	Id      string `xml:"Id"`
	SchmeNm string `xml:"SchmeNm"`
	Issr    string `xml:"Issr"`
}

// GenericIdentification30 ...
type GenericIdentification30 struct {
	Id      string `xml:"Id"`
	Issr    string `xml:"Issr"`
	SchmeNm string `xml:"SchmeNm"`
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

// GetTransactionV08 ...
type GetTransactionV08 struct {
	MsgHdr      *MessageHeader9       `xml:"MsgHdr"`
	TxQryDef    *TransactionQuery5    `xml:"TxQryDef"`
	SplmtryData []*SupplementaryData1 `xml:"SplmtryData"`
}

// IBAN2007Identifier ...
type IBAN2007Identifier string

// ISODate ...
type ISODate string

// ISODateTime ...
type ISODateTime string

// ImpliedCurrencyAmountRange1Choice ...
type ImpliedCurrencyAmountRange1Choice struct {
	FrAmt   *AmountRangeBoundary1 `xml:"FrAmt"`
	ToAmt   *AmountRangeBoundary1 `xml:"ToAmt"`
	FrToAmt *FromToAmountRange1   `xml:"FrToAmt"`
	EQAmt   float64               `xml:"EQAmt"`
	NEQAmt  float64               `xml:"NEQAmt"`
}

// ImpliedCurrencyAndAmount ...
type ImpliedCurrencyAndAmount float64

// ImpliedCurrencyAndAmountRange1 ...
type ImpliedCurrencyAndAmountRange1 struct {
	Amt       *ImpliedCurrencyAmountRange1Choice `xml:"Amt"`
	CdtDbtInd string                             `xml:"CdtDbtInd"`
}

// Instruction1Code ...
type Instruction1Code string

// InstructionStatusReturnCriteria1 ...
type InstructionStatusReturnCriteria1 struct {
	PmtInstrStsInd     bool `xml:"PmtInstrStsInd"`
	PmtInstrStsDtTmInd bool `xml:"PmtInstrStsDtTmInd"`
	PmtInstrStsRsnInd  bool `xml:"PmtInstrStsRsnInd"`
}

// InstructionStatusSearch5 ...
type InstructionStatusSearch5 struct {
	PmtInstrSts     *PaymentStatusCodeSearch2Choice `xml:"PmtInstrSts"`
	PmtInstrStsDtTm *DateTimePeriod1Choice          `xml:"PmtInstrStsDtTm"`
	PrtryStsRsn     string                          `xml:"PrtryStsRsn"`
}

// LEIIdentifier ...
type LEIIdentifier string

// LongPaymentIdentification2 ...
type LongPaymentIdentification2 struct {
	TxId           string                                        `xml:"TxId"`
	UETR           string                                        `xml:"UETR"`
	IntrBkSttlmAmt float64                                       `xml:"IntrBkSttlmAmt"`
	IntrBkSttlmDt  string                                        `xml:"IntrBkSttlmDt"`
	PmtMtd         *PaymentOrigin1Choice                         `xml:"PmtMtd"`
	InstgAgt       *BranchAndFinancialInstitutionIdentification6 `xml:"InstgAgt"`
	InstdAgt       *BranchAndFinancialInstitutionIdentification6 `xml:"InstdAgt"`
	NtryTp         string                                        `xml:"NtryTp"`
	EndToEndId     string                                        `xml:"EndToEndId"`
}

// Max128Text ...
type Max128Text string

// Max140Text ...
type Max140Text string

// Max16Text ...
type Max16Text string

// Max2048Text ...
type Max2048Text string

// Max34Text ...
type Max34Text string

// Max350Text ...
type Max350Text string

// Max35Text ...
type Max35Text string

// Max3NumericText ...
type Max3NumericText string

// Max4AlphaNumericText ...
type Max4AlphaNumericText string

// Max4Text ...
type Max4Text string

// Max70Text ...
type Max70Text string

// MessageHeader9 ...
type MessageHeader9 struct {
	MsgId   string              `xml:"MsgId"`
	CreDtTm string              `xml:"CreDtTm"`
	ReqTp   *RequestType4Choice `xml:"ReqTp"`
}

// NamePrefix2Code ...
type NamePrefix2Code string

// OrganisationIdentification29 ...
type OrganisationIdentification29 struct {
	AnyBIC string                                `xml:"AnyBIC"`
	LEI    string                                `xml:"LEI"`
	Othr   []*GenericOrganisationIdentification1 `xml:"Othr"`
}

// OrganisationIdentificationSchemeName1Choice ...
type OrganisationIdentificationSchemeName1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// OtherContact1 ...
type OtherContact1 struct {
	ChanlTp string `xml:"ChanlTp"`
	Id      string `xml:"Id"`
}

// Party38Choice ...
type Party38Choice struct {
	OrgId  *OrganisationIdentification29 `xml:"OrgId"`
	PrvtId *PersonIdentification13       `xml:"PrvtId"`
}

// Party40Choice ...
type Party40Choice struct {
	Pty *PartyIdentification135                       `xml:"Pty"`
	Agt *BranchAndFinancialInstitutionIdentification6 `xml:"Agt"`
}

// PartyIdentification135 ...
type PartyIdentification135 struct {
	Nm        string           `xml:"Nm"`
	PstlAdr   *PostalAddress24 `xml:"PstlAdr"`
	Id        *Party38Choice   `xml:"Id"`
	CtryOfRes string           `xml:"CtryOfRes"`
	CtctDtls  *Contact4        `xml:"CtctDtls"`
}

// PaymentIdentification6Choice ...
type PaymentIdentification6Choice struct {
	TxId      string                           `xml:"TxId"`
	QId       *QueueTransactionIdentification1 `xml:"QId"`
	LngBizId  *LongPaymentIdentification2      `xml:"LngBizId"`
	ShrtBizId *ShortPaymentIdentification2     `xml:"ShrtBizId"`
	PrtryId   string                           `xml:"PrtryId"`
}

// PaymentInstrument1Code ...
type PaymentInstrument1Code string

// PaymentOrigin1Choice ...
type PaymentOrigin1Choice struct {
	FINMT    string `xml:"FINMT"`
	XMLMsgNm string `xml:"XMLMsgNm"`
	Prtry    string `xml:"Prtry"`
	Instrm   string `xml:"Instrm"`
}

// PaymentReturnCriteria4 ...
type PaymentReturnCriteria4 struct {
	MsgIdInd            bool                              `xml:"MsgIdInd"`
	ReqdExctnDtInd      bool                              `xml:"ReqdExctnDtInd"`
	InstrInd            bool                              `xml:"InstrInd"`
	InstrStsRtrCrit     *InstructionStatusReturnCriteria1 `xml:"InstrStsRtrCrit"`
	InstdAmtInd         bool                              `xml:"InstdAmtInd"`
	CdtDbtInd           bool                              `xml:"CdtDbtInd"`
	IntrBkSttlmAmtInd   bool                              `xml:"IntrBkSttlmAmtInd"`
	PrtyInd             bool                              `xml:"PrtyInd"`
	PrcgVldtyTmInd      bool                              `xml:"PrcgVldtyTmInd"`
	PurpInd             bool                              `xml:"PurpInd"`
	InstrCpyInd         bool                              `xml:"InstrCpyInd"`
	PmtMTInd            bool                              `xml:"PmtMTInd"`
	PmtTpInd            bool                              `xml:"PmtTpInd"`
	TxIdInd             bool                              `xml:"TxIdInd"`
	IntrBkSttlmDtInd    bool                              `xml:"IntrBkSttlmDtInd"`
	EndToEndIdInd       bool                              `xml:"EndToEndIdInd"`
	PmtMtdInd           bool                              `xml:"PmtMtdInd"`
	DbtrInd             bool                              `xml:"DbtrInd"`
	DbtrAgtInd          bool                              `xml:"DbtrAgtInd"`
	InstgRmbrsmntAgtInd bool                              `xml:"InstgRmbrsmntAgtInd"`
	InstdRmbrsmntAgtInd bool                              `xml:"InstdRmbrsmntAgtInd"`
	IntrmyInd           bool                              `xml:"IntrmyInd"`
	CdtrAgtInd          bool                              `xml:"CdtrAgtInd"`
	CdtrInd             bool                              `xml:"CdtrInd"`
}

// PaymentSearch8 ...
type PaymentSearch8 struct {
	MsgId             []string                              `xml:"MsgId"`
	ReqdExctnDt       []*DateAndDateTimeSearch3Choice       `xml:"ReqdExctnDt"`
	PmtId             []*PaymentIdentification6Choice       `xml:"PmtId"`
	Sts               []*InstructionStatusSearch5           `xml:"Sts"`
	InstdAmt          []*ActiveOrHistoricAmountRange2Choice `xml:"InstdAmt"`
	InstdAmtCcy       []string                              `xml:"InstdAmtCcy"`
	CdtDbtInd         string                                `xml:"CdtDbtInd"`
	IntrBkSttlmAmt    []*ActiveAmountRange3Choice           `xml:"IntrBkSttlmAmt"`
	IntrBkSttlmAmtCcy []string                              `xml:"IntrBkSttlmAmtCcy"`
	PmtMtd            []*PaymentOrigin1Choice               `xml:"PmtMtd"`
	PmtTp             []*PaymentType4Choice                 `xml:"PmtTp"`
	Prty              []*Priority1Choice                    `xml:"Prty"`
	PrcgVldtyTm       []*DateTimePeriod1Choice              `xml:"PrcgVldtyTm"`
	Instr             []string                              `xml:"Instr"`
	TxId              []string                              `xml:"TxId"`
	IntrBkSttlmDt     []string                              `xml:"IntrBkSttlmDt"`
	EndToEndId        []string                              `xml:"EndToEndId"`
	Pties             *PaymentTransactionParty3             `xml:"Pties"`
}

// PaymentStatusCodeSearch2Choice ...
type PaymentStatusCodeSearch2Choice struct {
	PdgSts       string `xml:"PdgSts"`
	FnlSts       string `xml:"FnlSts"`
	PdgAndFnlSts string `xml:"PdgAndFnlSts"`
}

// PaymentTransactionParty3 ...
type PaymentTransactionParty3 struct {
	InstgAgt         *BranchAndFinancialInstitutionIdentification6 `xml:"InstgAgt"`
	InstdAgt         *BranchAndFinancialInstitutionIdentification6 `xml:"InstdAgt"`
	UltmtDbtr        *Party40Choice                                `xml:"UltmtDbtr"`
	Dbtr             *Party40Choice                                `xml:"Dbtr"`
	DbtrAgt          *BranchAndFinancialInstitutionIdentification6 `xml:"DbtrAgt"`
	InstgRmbrsmntAgt *BranchAndFinancialInstitutionIdentification6 `xml:"InstgRmbrsmntAgt"`
	InstdRmbrsmntAgt *BranchAndFinancialInstitutionIdentification6 `xml:"InstdRmbrsmntAgt"`
	IntrmyAgt1       *BranchAndFinancialInstitutionIdentification6 `xml:"IntrmyAgt1"`
	IntrmyAgt2       *BranchAndFinancialInstitutionIdentification6 `xml:"IntrmyAgt2"`
	IntrmyAgt3       *BranchAndFinancialInstitutionIdentification6 `xml:"IntrmyAgt3"`
	CdtrAgt          *BranchAndFinancialInstitutionIdentification6 `xml:"CdtrAgt"`
	Cdtr             *Party40Choice                                `xml:"Cdtr"`
	UltmtCdtr        *Party40Choice                                `xml:"UltmtCdtr"`
}

// PaymentType3Code ...
type PaymentType3Code string

// PaymentType4Choice ...
type PaymentType4Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// PendingStatus4Code ...
type PendingStatus4Code string

// PersonIdentification13 ...
type PersonIdentification13 struct {
	DtAndPlcOfBirth *DateAndPlaceOfBirth1           `xml:"DtAndPlcOfBirth"`
	Othr            []*GenericPersonIdentification1 `xml:"Othr"`
}

// PersonIdentificationSchemeName1Choice ...
type PersonIdentificationSchemeName1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// PhoneNumber ...
type PhoneNumber string

// PostalAddress24 ...
type PostalAddress24 struct {
	AdrTp       *AddressType3Choice `xml:"AdrTp"`
	Dept        string              `xml:"Dept"`
	SubDept     string              `xml:"SubDept"`
	StrtNm      string              `xml:"StrtNm"`
	BldgNb      string              `xml:"BldgNb"`
	BldgNm      string              `xml:"BldgNm"`
	Flr         string              `xml:"Flr"`
	PstBx       string              `xml:"PstBx"`
	Room        string              `xml:"Room"`
	PstCd       string              `xml:"PstCd"`
	TwnNm       string              `xml:"TwnNm"`
	TwnLctnNm   string              `xml:"TwnLctnNm"`
	DstrctNm    string              `xml:"DstrctNm"`
	CtrySubDvsn string              `xml:"CtrySubDvsn"`
	Ctry        string              `xml:"Ctry"`
	AdrLine     []string            `xml:"AdrLine"`
}

// PreferredContactMethod1Code ...
type PreferredContactMethod1Code string

// Priority1Choice ...
type Priority1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// Priority5Code ...
type Priority5Code string

// QueryType2Code ...
type QueryType2Code string

// QueueTransactionIdentification1 ...
type QueueTransactionIdentification1 struct {
	QId    string `xml:"QId"`
	PosInQ string `xml:"PosInQ"`
}

// ReportIndicator1Code ...
type ReportIndicator1Code string

// RequestType4Choice ...
type RequestType4Choice struct {
	PmtCtrl string                  `xml:"PmtCtrl"`
	Enqry   string                  `xml:"Enqry"`
	Prtry   *GenericIdentification1 `xml:"Prtry"`
}

// RequestedIndicator ...
type RequestedIndicator bool

// ShortPaymentIdentification2 ...
type ShortPaymentIdentification2 struct {
	TxId          string                                        `xml:"TxId"`
	IntrBkSttlmDt string                                        `xml:"IntrBkSttlmDt"`
	InstgAgt      *BranchAndFinancialInstitutionIdentification6 `xml:"InstgAgt"`
}

// SupplementaryData1 ...
type SupplementaryData1 struct {
	PlcAndNm string                      `xml:"PlcAndNm"`
	Envlp    *SupplementaryDataEnvelope1 `xml:"Envlp"`
}

// SupplementaryDataEnvelope1 ...
type SupplementaryDataEnvelope1 struct {
}

// SystemReturnCriteria2 ...
type SystemReturnCriteria2 struct {
	SysIdInd  bool `xml:"SysIdInd"`
	MmbIdInd  bool `xml:"MmbIdInd"`
	CtryIdInd bool `xml:"CtryIdInd"`
	AcctIdInd bool `xml:"AcctIdInd"`
}

// SystemSearch4 ...
type SystemSearch4 struct {
	SysId  []*ClearingSystemIdentification3Choice          `xml:"SysId"`
	MmbId  []*BranchAndFinancialInstitutionIdentification6 `xml:"MmbId"`
	Ctry   string                                          `xml:"Ctry"`
	AcctId *AccountIdentification4Choice                   `xml:"AcctId"`
}

// TransactionCriteria5Choice ...
type TransactionCriteria5Choice struct {
	QryNm   string                `xml:"QryNm"`
	NewCrit *TransactionCriteria8 `xml:"NewCrit"`
}

// TransactionCriteria8 ...
type TransactionCriteria8 struct {
	NewQryNm string                        `xml:"NewQryNm"`
	SchCrit  []*TransactionSearchCriteria8 `xml:"SchCrit"`
	StmtRpt  string                        `xml:"StmtRpt"`
	RtrCrit  *TransactionReturnCriteria5   `xml:"RtrCrit"`
}

// TransactionQuery5 ...
type TransactionQuery5 struct {
	QryTp  string                      `xml:"QryTp"`
	TxCrit *TransactionCriteria5Choice `xml:"TxCrit"`
}

// TransactionReturnCriteria5 ...
type TransactionReturnCriteria5 struct {
	PmtToRtrCrit       *SystemReturnCriteria2           `xml:"PmtToRtrCrit"`
	PmtFrRtrCrit       *SystemReturnCriteria2           `xml:"PmtFrRtrCrit"`
	AcctCshNtryRtrCrit *AccountCashEntryReturnCriteria3 `xml:"AcctCshNtryRtrCrit"`
	PmtRtrCrit         *PaymentReturnCriteria4          `xml:"PmtRtrCrit"`
}

// TransactionSearchCriteria8 ...
type TransactionSearchCriteria8 struct {
	PmtTo       []*SystemSearch4         `xml:"PmtTo"`
	PmtFr       []*SystemSearch4         `xml:"PmtFr"`
	PmtSch      *PaymentSearch8          `xml:"PmtSch"`
	AcctNtrySch *CashAccountEntrySearch6 `xml:"AcctNtrySch"`
}

// UUIDv4Identifier ...
type UUIDv4Identifier string

// YesNoIndicator ...
type YesNoIndicator bool
