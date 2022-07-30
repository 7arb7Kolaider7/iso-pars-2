package schema

import (
	"encoding/xml"
)

// Document ...
type Document *Document

// Account1 ...
type Account1 struct {
	Id       *AccountIdentification1     `xml:"Id"`
	AcctSvcr *PartyIdentification1Choice `xml:"AcctSvcr"`
}

// AccountIdentification1 ...
type AccountIdentification1 struct {
	Prtry *SimpleIdentificationInformation `xml:"Prtry"`
}

// AccountIdentification1Choice ...
type AccountIdentification1Choice struct {
	IBAN     string                           `xml:"IBAN"`
	BBAN     string                           `xml:"BBAN"`
	UPIC     string                           `xml:"UPIC"`
	DmstAcct *SimpleIdentificationInformation `xml:"DmstAcct"`
}

// AddressType2Code ...
type AddressType2Code string

// AmountType1Choice ...
type AmountType1Choice struct {
	InstdAmt *CurrencyAndAmount `xml:"InstdAmt"`
	EqvtAmt  *EquivalentAmount  `xml:"EqvtAmt"`
}

// AnyBICIdentifier ...
type AnyBICIdentifier string

// AustrianBankleitzahlIdentifier ...
type AustrianBankleitzahlIdentifier string

// BBANIdentifier ...
type BBANIdentifier string

// BEIIdentifier ...
type BEIIdentifier string

// BICIdentifier ...
type BICIdentifier string

// BranchAndFinancialInstitutionIdentification ...
type BranchAndFinancialInstitutionIdentification struct {
	FinInstnId *FinancialInstitutionIdentification1 `xml:"FinInstnId"`
	BrnchId    *BranchData                          `xml:"BrnchId"`
}

// BranchData ...
type BranchData struct {
	Id      string          `xml:"Id"`
	Nm      string          `xml:"Nm"`
	PstlAdr *PostalAddress1 `xml:"PstlAdr"`
}

// CHIPSParticipantIdentifier ...
type CHIPSParticipantIdentifier string

// CHIPSUniversalIdentifier ...
type CHIPSUniversalIdentifier string

// CanadianPaymentsARNIdentifier ...
type CanadianPaymentsARNIdentifier string

// Case ...
type Case struct {
	Id             string `xml:"Id"`
	Cretr          string `xml:"Cretr"`
	ReopCaseIndctn bool   `xml:"ReopCaseIndctn"`
}

// CaseAssignment ...
type CaseAssignment struct {
	Id      string `xml:"Id"`
	Assgnr  string `xml:"Assgnr"`
	Assgne  string `xml:"Assgne"`
	CreDtTm string `xml:"CreDtTm"`
}

// CashAccount3 ...
type CashAccount3 struct {
	Id  *AccountIdentification1Choice `xml:"Id"`
	Tp  string                        `xml:"Tp"`
	Ccy string                        `xml:"Ccy"`
	Nm  string                        `xml:"Nm"`
}

// CashAccountType3Code ...
type CashAccountType3Code string

// ClearingSystemMemberIdentificationChoice ...
type ClearingSystemMemberIdentificationChoice struct {
	USCHU  string `xml:"USCHU"`
	NZNCC  string `xml:"NZNCC"`
	IENSC  string `xml:"IENSC"`
	GBSC   string `xml:"GBSC"`
	USCH   string `xml:"USCH"`
	CHBC   string `xml:"CHBC"`
	USFW   string `xml:"USFW"`
	PTNCC  string `xml:"PTNCC"`
	RUCB   string `xml:"RUCB"`
	ITNCC  string `xml:"ITNCC"`
	ATBLZ  string `xml:"ATBLZ"`
	CACPA  string `xml:"CACPA"`
	CHSIC  string `xml:"CHSIC"`
	DEBLZ  string `xml:"DEBLZ"`
	ESNCC  string `xml:"ESNCC"`
	ZANCC  string `xml:"ZANCC"`
	HKNCC  string `xml:"HKNCC"`
	AUBSBx string `xml:"AUBSBx"`
	AUBSBs string `xml:"AUBSBs"`
}

// CountryCode ...
type CountryCode string

// CurrencyAndAmountSimpleType ...
type CurrencyAndAmountSimpleType float64

// CurrencyAndAmount ...
type CurrencyAndAmount struct {
	CcyAttr string  `xml:"Ccy,attr"`
	Value   float64 `xml:",chardata"`
}

// CurrencyCode ...
type CurrencyCode string

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

// ExtensiveBranchNetworkIdentifier ...
type ExtensiveBranchNetworkIdentifier string

// FedwireRoutingNumberIdentifier ...
type FedwireRoutingNumberIdentifier string

// FinancialInstitutionIdentification1 ...
type FinancialInstitutionIdentification1 struct {
	BIC         string                                    `xml:"BIC"`
	ClrSysMmbId *ClearingSystemMemberIdentificationChoice `xml:"ClrSysMmbId"`
	Nm          string                                    `xml:"Nm"`
	PstlAdr     *PostalAddress1                           `xml:"PstlAdr"`
	PrtryId     *GenericIdentification3                   `xml:"PrtryId"`
}

// GenericIdentification1 ...
type GenericIdentification1 struct {
	Id      string `xml:"Id"`
	SchmeNm string `xml:"SchmeNm"`
	Issr    string `xml:"Issr"`
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

// GermanBankleitzahlIdentifier ...
type GermanBankleitzahlIdentifier string

// HongKongBankIdentifier ...
type HongKongBankIdentifier string

// IBANIdentifier ...
type IBANIdentifier string

// ISODate ...
type ISODate string

// ISODateTime ...
type ISODateTime string

// Intermediary1 ...
type Intermediary1 struct {
	Id   *PartyIdentification1Choice `xml:"Id"`
	Acct *Account1                   `xml:"Acct"`
	Role string                      `xml:"Role"`
}

// IrishNSCIdentifier ...
type IrishNSCIdentifier string

// ItalianDomesticIdentifier ...
type ItalianDomesticIdentifier string

// LongPostalAddress1Choice ...
type LongPostalAddress1Choice struct {
	Ustrd string                        `xml:"Ustrd"`
	Strd  *StructuredLongPostalAddress1 `xml:"Strd"`
}

// Max140Text ...
type Max140Text string

// Max16Text ...
type Max16Text string

// Max35Text ...
type Max35Text string

// Max70Text ...
type Max70Text string

// NameAndAddress2 ...
type NameAndAddress2 struct {
	Nm  string                    `xml:"Nm"`
	Adr *LongPostalAddress1Choice `xml:"Adr"`
}

// NewZealandNCCIdentifier ...
type NewZealandNCCIdentifier string

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

// PartyIdentification1Choice ...
type PartyIdentification1Choice struct {
	BICOrBEI string                  `xml:"BICOrBEI"`
	PrtryId  *GenericIdentification1 `xml:"PrtryId"`
	NmAndAdr *NameAndAddress2        `xml:"NmAndAdr"`
}

// PaymentComplementaryInformation ...
type PaymentComplementaryInformation struct {
	RmtChc         *RemittanceInformation3Choice                `xml:"RmtChc"`
	Dbtr           *PartyIdentification1                        `xml:"Dbtr"`
	DbtrAcct       *CashAccount3                                `xml:"DbtrAcct"`
	FrstAgt        *BranchAndFinancialInstitutionIdentification `xml:"FrstAgt"`
	Amt            *AmountType1Choice                           `xml:"Amt"`
	NstrVstrAcct   *CashAccount3                                `xml:"NstrVstrAcct"`
	Intrmy         *Intermediary1                               `xml:"Intrmy"`
	FrstSttlmAgt   *BranchAndFinancialInstitutionIdentification `xml:"FrstSttlmAgt"`
	LastSttlmAgt   *BranchAndFinancialInstitutionIdentification `xml:"LastSttlmAgt"`
	IntrmySttlmAgt *BranchAndFinancialInstitutionIdentification `xml:"IntrmySttlmAgt"`
	Cdtr           *PartyIdentification1                        `xml:"Cdtr"`
	CdtrAcct       *CashAccount3                                `xml:"CdtrAcct"`
	SndrToRcvrInf  []string                                     `xml:"SndrToRcvrInf"`
}

// PaymentInstructionExtract ...
type PaymentInstructionExtract struct {
	AssgnrInstrId string             `xml:"AssgnrInstrId"`
	AssgneInstrId string             `xml:"AssgneInstrId"`
	CcyAmt        *CurrencyAndAmount `xml:"CcyAmt"`
	ValDt         string             `xml:"ValDt"`
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

// PortugueseNCCIdentifier ...
type PortugueseNCCIdentifier string

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

// RussianCentralBankIdentificationCodeIdentifier ...
type RussianCentralBankIdentificationCodeIdentifier string

// SimpleIdentificationInformation ...
type SimpleIdentificationInformation struct {
	Id string `xml:"Id"`
}

// SmallNetworkIdentifier ...
type SmallNetworkIdentifier string

// SouthAfricanNCCIdentifier ...
type SouthAfricanNCCIdentifier string

// SpanishDomesticInterbankingIdentifier ...
type SpanishDomesticInterbankingIdentifier string

// StructuredLongPostalAddress1 ...
type StructuredLongPostalAddress1 struct {
	BldgNm     string `xml:"BldgNm"`
	StrtNm     string `xml:"StrtNm"`
	StrtBldgId string `xml:"StrtBldgId"`
	Flr        string `xml:"Flr"`
	TwnNm      string `xml:"TwnNm"`
	DstrctNm   string `xml:"DstrctNm"`
	RgnId      string `xml:"RgnId"`
	Stat       string `xml:"Stat"`
	CtyId      string `xml:"CtyId"`
	Ctry       string `xml:"Ctry"`
	PstCdId    string `xml:"PstCdId"`
	POB        string `xml:"POB"`
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

// SwissBCIdentifier ...
type SwissBCIdentifier string

// SwissSICIdentifier ...
type SwissSICIdentifier string

// UKDomesticSortCodeIdentifier ...
type UKDomesticSortCodeIdentifier string

// UPICIdentifier ...
type UPICIdentifier string

// YesNoIndicator ...
type YesNoIndicator bool

// Camt02800101 ...
type Camt02800101 struct {
	XMLName xml.Name                         `xml:"camt.028.001.01"`
	Assgnmt *CaseAssignment                  `xml:"Assgnmt"`
	Case    *Case                            `xml:"Case"`
	Undrlyg *PaymentInstructionExtract       `xml:"Undrlyg"`
	Inf     *PaymentComplementaryInformation `xml:"Inf"`
}
