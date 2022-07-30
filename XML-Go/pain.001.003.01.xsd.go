package schema

import (
	"encoding/xml"
)

// Document ...
type Document *Document

// AccountIdentification1Choice ...
type AccountIdentification1Choice struct {
	IBAN     string                           `xml:"IBAN"`
	BBAN     string                           `xml:"BBAN"`
	UPIC     string                           `xml:"UPIC"`
	DmstAcct *SimpleIdentificationInformation `xml:"DmstAcct"`
}

// AccountIdentification2 ...
type AccountIdentification2 struct {
	IBAN string `xml:"IBAN"`
}

// AddressType2Code ...
type AddressType2Code string

// AmountType1Choice ...
type AmountType1Choice struct {
	InstdAmt *CurrencyAndAmount `xml:"InstdAmt"`
	EqvtAmt  *EquivalentAmount  `xml:"EqvtAmt"`
}

// BBANIdentifier ...
type BBANIdentifier string

// BEIIdentifier ...
type BEIIdentifier string

// BICIdentification1 ...
type BICIdentification1 struct {
	BIC string `xml:"BIC"`
}

// BICIdentifier ...
type BICIdentifier string

// BatchBookingIndicator ...
type BatchBookingIndicator bool

// CHIPSUniversalIdentifier ...
type CHIPSUniversalIdentifier string

// CashAccount3 ...
type CashAccount3 struct {
	Id  *AccountIdentification1Choice `xml:"Id"`
	Tp  string                        `xml:"Tp"`
	Ccy string                        `xml:"Ccy"`
	Nm  string                        `xml:"Nm"`
}

// CashAccountType3Code ...
type CashAccountType3Code string

// CashClearingSystem2Code ...
type CashClearingSystem2Code string

// ChargeBearer1Code ...
type ChargeBearer1Code string

// CountryCode ...
type CountryCode string

// CreditTransferType2Code ...
type CreditTransferType2Code string

// CreditTransferTypeIdentification ...
type CreditTransferTypeIdentification struct {
	Cd        string                    `xml:"Cd"`
	LclInstrm string                    `xml:"LclInstrm"`
	InstrPrty string                    `xml:"InstrPrty"`
	SttlmPrty *SettlementPriorityChoice `xml:"SttlmPrty"`
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

// DecimalNumber ...
type DecimalNumber float64

// DocumentType1Code ...
type DocumentType1Code string

// DunsIdentifier ...
type DunsIdentifier string

// EANGLNIdentifier ...
type EANGLNIdentifier string

// EquivalentAmount ...
type EquivalentAmount struct {
	Amt      *CurrencyAndAmount `xml:"Amt"`
	CcyOfTrf string             `xml:"CcyOfTrf"`
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

// GenericPaymentTransaction2 ...
type GenericPaymentTransaction2 struct {
	PmtId         *PaymentIdentification        `xml:"PmtId"`
	Purp          *PurposeChoice                `xml:"Purp"`
	Amt           *AmountType1Choice            `xml:"Amt"`
	Cdtr          *PartyIdentification1         `xml:"Cdtr"`
	CdtrCtryOfRes string                        `xml:"CdtrCtryOfRes"`
	FnlAgt        *BICIdentification1           `xml:"FnlAgt"`
	ChrgBr        string                        `xml:"ChrgBr"`
	CdtrAcct      *AccountIdentification2       `xml:"CdtrAcct"`
	XchgCtrctRef  string                        `xml:"XchgCtrctRef"`
	RmtInf        *RemittanceInformation3Choice `xml:"RmtInf"`
}

// GroupInformation2 ...
type GroupInformation2 struct {
	GrpId     string                `xml:"GrpId"`
	CreDtTm   string                `xml:"CreDtTm"`
	Authstn   []string              `xml:"Authstn"`
	CtrlSum   float64               `xml:"CtrlSum"`
	BtchBookg bool                  `xml:"BtchBookg"`
	NbOfTxs   string                `xml:"NbOfTxs"`
	Grpg      bool                  `xml:"Grpg"`
	InitgPty  *PartyIdentification1 `xml:"InitgPty"`
	FwdgAgt   *BICIdentification1   `xml:"FwdgAgt"`
}

// GroupingIndicator ...
type GroupingIndicator bool

// IBANIdentifier ...
type IBANIdentifier string

// ISODate ...
type ISODate string

// ISODateTime ...
type ISODateTime string

// Max128Text ...
type Max128Text string

// Max140Text ...
type Max140Text string

// Max15NumericText ...
type Max15NumericText string

// Max16Text ...
type Max16Text string

// Max35Text ...
type Max35Text string

// Max70Text ...
type Max70Text string

// NonFinancialInstitutionIdentification1 ...
type NonFinancialInstitutionIdentification1 struct {
	BEI     string                  `xml:"BEI"`
	EANGLN  string                  `xml:"EANGLN"`
	USCHU   string                  `xml:"USCHU"`
	DUNS    string                  `xml:"DUNS"`
	BkPtyId string                  `xml:"BkPtyId"`
	TaxIdNb string                  `xml:"TaxIdNb"`
	PrtryId *GenericIdentification3 `xml:"PrtryId"`
}

// Party1Choice ...
type Party1Choice struct {
	OrgId  *NonFinancialInstitutionIdentification1 `xml:"OrgId"`
	PrvtId []*PersonIdentification2                `xml:"PrvtId"`
}

// PartyIdentification1 ...
type PartyIdentification1 struct {
	Nm      string          `xml:"Nm"`
	PstlAdr *PostalAddress1 `xml:"PstlAdr"`
	Id      *Party1Choice   `xml:"Id"`
}

// PaymentIdentification ...
type PaymentIdentification struct {
	InstrId    string `xml:"InstrId"`
	EndToEndId string `xml:"EndToEndId"`
	PmtRmtId   string `xml:"PmtRmtId"`
}

// PaymentInformation7 ...
type PaymentInformation7 struct {
	ReqdExctnDt   string                            `xml:"ReqdExctnDt"`
	CdtTrfTpId    *CreditTransferTypeIdentification `xml:"CdtTrfTpId"`
	Dbtr          *PartyIdentification1             `xml:"Dbtr"`
	DbtrCtryOfRes string                            `xml:"DbtrCtryOfRes"`
	DbtrAcct      *CashAccount3                     `xml:"DbtrAcct"`
	FrstAgt       *BICIdentification1               `xml:"FrstAgt"`
	ChrgsAcct     *CashAccount3                     `xml:"ChrgsAcct"`
	ChrgsAcctAgt  *BICIdentification1               `xml:"ChrgsAcctAgt"`
	PmtTx         []*GenericPaymentTransaction2     `xml:"PmtTx"`
}

// PaymentPurpose1Code ...
type PaymentPurpose1Code string

// PaymentSchemeChoice ...
type PaymentSchemeChoice struct {
	Cd       string `xml:"Cd"`
	PrtryInf string `xml:"PrtryInf"`
}

// PersonIdentification2 ...
type PersonIdentification2 struct {
	DrvrsLicNb  string                  `xml:"DrvrsLicNb"`
	SclSctyNb   string                  `xml:"SclSctyNb"`
	AlnRegnNb   string                  `xml:"AlnRegnNb"`
	PsptNb      string                  `xml:"PsptNb"`
	TaxIdNb     string                  `xml:"TaxIdNb"`
	IdntyCardNb string                  `xml:"IdntyCardNb"`
	MplyrIdNb   string                  `xml:"MplyrIdNb"`
	OthrId      *GenericIdentification4 `xml:"OthrId"`
	Issr        string                  `xml:"Issr"`
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

// PurposeChoice ...
type PurposeChoice struct {
	Prtry string `xml:"Prtry"`
	Cd    string `xml:"Cd"`
}

// ReferredDocumentAmount1Choice ...
type ReferredDocumentAmount1Choice struct {
	DuePyblAmt   *CurrencyAndAmount `xml:"DuePyblAmt"`
	DscntApldAmt *CurrencyAndAmount `xml:"DscntApldAmt"`
	RmtdAmt      *CurrencyAndAmount `xml:"RmtdAmt"`
	CdtNoteAmt   *CurrencyAndAmount `xml:"CdtNoteAmt"`
	TaxAmt       *CurrencyAndAmount `xml:"TaxAmt"`
}

// RemittanceInformation3Choice ...
type RemittanceInformation3Choice struct {
	Ustrd string                            `xml:"Ustrd"`
	Strd  *StructuredRemittanceInformation2 `xml:"Strd"`
}

// SettlementPriorityChoice ...
type SettlementPriorityChoice struct {
	Prty     string               `xml:"Prty"`
	PmtSchme *PaymentSchemeChoice `xml:"PmtSchme"`
}

// SimpleIdentificationInformation ...
type SimpleIdentificationInformation struct {
	Id string `xml:"Id"`
}

// StructuredRemittanceInformation2 ...
type StructuredRemittanceInformation2 struct {
	RfrdDocTp     string                           `xml:"RfrdDocTp"`
	RfrdDocRltdDt string                           `xml:"RfrdDocRltdDt"`
	RfrdDocAmt    []*ReferredDocumentAmount1Choice `xml:"RfrdDocAmt"`
	DocRefNb      string                           `xml:"DocRefNb"`
	CdtrRef       string                           `xml:"CdtrRef"`
	Invcr         *PartyIdentification1            `xml:"Invcr"`
	Invcee        *PartyIdentification1            `xml:"Invcee"`
}

// UPICIdentifier ...
type UPICIdentifier string

// Pain00100301 ...
type Pain00100301 struct {
	XMLName xml.Name               `xml:"pain.001.003.01"`
	GrpHdr  *GroupInformation2     `xml:"GrpHdr"`
	PmtInf  []*PaymentInformation7 `xml:"PmtInf"`
}
