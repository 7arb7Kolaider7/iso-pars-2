package schema

import (
	"encoding/xml"
)

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

// AmendmentInformationDetails1 ...
type AmendmentInformationDetails1 struct {
	OrgnlMndtId      string                                        `xml:"OrgnlMndtId"`
	OrgnlCdtrSchmeId *PartyIdentification8                         `xml:"OrgnlCdtrSchmeId"`
	OrgnlCdtrAgt     *BranchAndFinancialInstitutionIdentification3 `xml:"OrgnlCdtrAgt"`
	OrgnlCdtrAgtAcct *CashAccount7                                 `xml:"OrgnlCdtrAgtAcct"`
	OrgnlDbtr        *PartyIdentification8                         `xml:"OrgnlDbtr"`
	OrgnlDbtrAcct    *CashAccount7                                 `xml:"OrgnlDbtrAcct"`
	OrgnlDbtrAgt     *BranchAndFinancialInstitutionIdentification3 `xml:"OrgnlDbtrAgt"`
	OrgnlDbtrAgtAcct *CashAccount7                                 `xml:"OrgnlDbtrAgtAcct"`
	OrgnlFnlColltnDt string                                        `xml:"OrgnlFnlColltnDt"`
	OrgnlFrqcy       string                                        `xml:"OrgnlFrqcy"`
}

// BBANIdentifier ...
type BBANIdentifier string

// BEIIdentifier ...
type BEIIdentifier string

// BICIdentifier ...
type BICIdentifier string

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

// ClearingChannel2Code ...
type ClearingChannel2Code string

// ClearingSystemMemberIdentification3Choice ...
type ClearingSystemMemberIdentification3Choice struct {
	Id    string `xml:"Id"`
	Prtry string `xml:"Prtry"`
}

// CountryCode ...
type CountryCode string

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

// DirectDebitTransaction1 ...
type DirectDebitTransaction1 struct {
	MndtRltdInf *MandateRelatedInformation1 `xml:"MndtRltdInf"`
	CdtrSchmeId *PartyIdentification8       `xml:"CdtrSchmeId"`
	PreNtfctnId string                      `xml:"PreNtfctnId"`
	PreNtfctnDt string                      `xml:"PreNtfctnDt"`
}

// DirectDebitTransactionInformation1 ...
type DirectDebitTransactionInformation1 struct {
	PmtId           *PaymentIdentification1                       `xml:"PmtId"`
	PmtTpInf        *PaymentTypeInformation2                      `xml:"PmtTpInf"`
	InstdAmt        *CurrencyAndAmount                            `xml:"InstdAmt"`
	ChrgBr          string                                        `xml:"ChrgBr"`
	DrctDbtTx       *DirectDebitTransaction1                      `xml:"DrctDbtTx"`
	UltmtCdtr       *PartyIdentification8                         `xml:"UltmtCdtr"`
	DbtrAgt         *BranchAndFinancialInstitutionIdentification3 `xml:"DbtrAgt"`
	DbtrAgtAcct     *CashAccount7                                 `xml:"DbtrAgtAcct"`
	Dbtr            *PartyIdentification8                         `xml:"Dbtr"`
	DbtrAcct        *CashAccount7                                 `xml:"DbtrAcct"`
	UltmtDbtr       *PartyIdentification8                         `xml:"UltmtDbtr"`
	InstrForCdtrAgt string                                        `xml:"InstrForCdtrAgt"`
	Purp            *Purpose1Choice                               `xml:"Purp"`
	RgltryRptg      []*RegulatoryReporting2                       `xml:"RgltryRptg"`
	Tax             *TaxInformation2                              `xml:"Tax"`
	RltdRmtInf      []*RemittanceLocation1                        `xml:"RltdRmtInf"`
	RmtInf          *RemittanceInformation1                       `xml:"RmtInf"`
}

// DocumentType2Code ...
type DocumentType2Code string

// DocumentType3Code ...
type DocumentType3Code string

// DunsIdentifier ...
type DunsIdentifier string

// EANGLNIdentifier ...
type EANGLNIdentifier string

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

// Frequency1Code ...
type Frequency1Code string

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

// LocalInstrument1Choice ...
type LocalInstrument1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// MandateRelatedInformation1 ...
type MandateRelatedInformation1 struct {
	MndtId        string                        `xml:"MndtId"`
	DtOfSgntr     string                        `xml:"DtOfSgntr"`
	AmdmntInd     bool                          `xml:"AmdmntInd"`
	AmdmntInfDtls *AmendmentInformationDetails1 `xml:"AmdmntInfDtls"`
	ElctrncSgntr  string                        `xml:"ElctrncSgntr"`
	FrstColltnDt  string                        `xml:"FrstColltnDt"`
	FnlColltnDt   string                        `xml:"FnlColltnDt"`
	Frqcy         string                        `xml:"Frqcy"`
}

// Max1025Text ...
type Max1025Text string

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

// PaymentInstructionInformation2 ...
type PaymentInstructionInformation2 struct {
	PmtInfId     string                                        `xml:"PmtInfId"`
	PmtMtd       string                                        `xml:"PmtMtd"`
	PmtTpInf     *PaymentTypeInformation2                      `xml:"PmtTpInf"`
	ReqdColltnDt string                                        `xml:"ReqdColltnDt"`
	Cdtr         *PartyIdentification8                         `xml:"Cdtr"`
	CdtrAcct     *CashAccount7                                 `xml:"CdtrAcct"`
	CdtrAgt      *BranchAndFinancialInstitutionIdentification3 `xml:"CdtrAgt"`
	CdtrAgtAcct  *CashAccount7                                 `xml:"CdtrAgtAcct"`
	UltmtCdtr    *PartyIdentification8                         `xml:"UltmtCdtr"`
	ChrgBr       string                                        `xml:"ChrgBr"`
	ChrgsAcct    *CashAccount7                                 `xml:"ChrgsAcct"`
	ChrgsAcctAgt *BranchAndFinancialInstitutionIdentification3 `xml:"ChrgsAcctAgt"`
	DrctDbtTxInf []*DirectDebitTransactionInformation1         `xml:"DrctDbtTxInf"`
}

// PaymentMethod2Code ...
type PaymentMethod2Code string

// PaymentTypeInformation2 ...
type PaymentTypeInformation2 struct {
	InstrPrty string                  `xml:"InstrPrty"`
	SvcLvl    *ServiceLevel3Choice    `xml:"SvcLvl"`
	ClrChanl  string                  `xml:"ClrChanl"`
	LclInstrm *LocalInstrument1Choice `xml:"LclInstrm"`
	SeqTp     string                  `xml:"SeqTp"`
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

// SequenceType1Code ...
type SequenceType1Code string

// ServiceLevel2Code ...
type ServiceLevel2Code string

// ServiceLevel3Choice ...
type ServiceLevel3Choice struct {
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

// TrueFalseIndicator ...
type TrueFalseIndicator bool

// UPICIdentifier ...
type UPICIdentifier string

// Pain00800101 ...
type Pain00800101 struct {
	XMLName xml.Name                          `xml:"pain.008.001.01"`
	GrpHdr  *GroupHeader1                     `xml:"GrpHdr"`
	PmtInf  []*PaymentInstructionInformation2 `xml:"PmtInf"`
}
