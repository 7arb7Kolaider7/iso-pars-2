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

// AddressType2Code ...
type AddressType2Code string

// AmountType1Choice ...
type AmountType1Choice struct {
	InstdAmt *CurrencyAndAmount `xml:"InstdAmt"`
	EqvtAmt  *EquivalentAmount  `xml:"EqvtAmt"`
}

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

// GeneralInformation1 ...
type GeneralInformation1 struct {
	PmtInitnStsId string                                       `xml:"PmtInitnStsId"`
	CreDtTm       string                                       `xml:"CreDtTm"`
	FwdgAgt       *BranchAndFinancialInstitutionIdentification `xml:"FwdgAgt"`
	InitgPty      *PartyIdentification1                        `xml:"InitgPty"`
	FrstAgt       *BranchAndFinancialInstitutionIdentification `xml:"FrstAgt"`
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

// IrishNSCIdentifier ...
type IrishNSCIdentifier string

// ItalianDomesticIdentifier ...
type ItalianDomesticIdentifier string

// Max105Text ...
type Max105Text string

// Max16Text ...
type Max16Text string

// Max35Text ...
type Max35Text string

// Max70Text ...
type Max70Text string

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

// OriginalGroupReferenceInformation1 ...
type OriginalGroupReferenceInformation1 struct {
	GrpId      string `xml:"GrpId"`
	OrgnlMsgTp string `xml:"OrgnlMsgTp"`
	GrpSts     string `xml:"GrpSts"`
	StsRsn     string `xml:"StsRsn"`
	AddtlInf   string `xml:"AddtlInf"`
}

// OriginalTransactionInformation1 ...
type OriginalTransactionInformation1 struct {
	Amt      *AmountType1Choice                           `xml:"Amt"`
	Cdtr     *PartyIdentification1                        `xml:"Cdtr"`
	CdtrAcct *CashAccount3                                `xml:"CdtrAcct"`
	FnlAgt   *BranchAndFinancialInstitutionIdentification `xml:"FnlAgt"`
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

// PaymentGroupStatusCode ...
type PaymentGroupStatusCode string

// PaymentIdentification ...
type PaymentIdentification struct {
	InstrId    string `xml:"InstrId"`
	EndToEndId string `xml:"EndToEndId"`
	PmtRmtId   string `xml:"PmtRmtId"`
}

// PaymentInformation9 ...
type PaymentInformation9 struct {
	ReqdExctnDt         string                            `xml:"ReqdExctnDt"`
	PmtMtdByFrstAgt     string                            `xml:"PmtMtdByFrstAgt"`
	CdtTrfTpId          *CreditTransferTypeIdentification `xml:"CdtTrfTpId"`
	Dbtr                *PartyIdentification1             `xml:"Dbtr"`
	DbtrAcct            *CashAccount3                     `xml:"DbtrAcct"`
	OrgnlTxRefInfAndSts []*PaymentReference1              `xml:"OrgnlTxRefInfAndSts"`
}

// PaymentMethod1Code ...
type PaymentMethod1Code string

// PaymentReference1 ...
type PaymentReference1 struct {
	PmtId      *PaymentIdentification           `xml:"PmtId"`
	TxSts      string                           `xml:"TxSts"`
	StsRsn     string                           `xml:"StsRsn"`
	AddtlInf   string                           `xml:"AddtlInf"`
	OrgnlTxInf *OriginalTransactionInformation1 `xml:"OrgnlTxInf"`
}

// PaymentReject1Code ...
type PaymentReject1Code string

// PaymentSchemeChoice ...
type PaymentSchemeChoice struct {
	Cd       string `xml:"Cd"`
	PrtryInf string `xml:"PrtryInf"`
}

// PaymentTransactionStatusCode ...
type PaymentTransactionStatusCode string

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

// Priority2Code ...
type Priority2Code string

// RussianCentralBankIdentificationCodeIdentifier ...
type RussianCentralBankIdentificationCodeIdentifier string

// SettlementPriorityChoice ...
type SettlementPriorityChoice struct {
	Prty     string               `xml:"Prty"`
	PmtSchme *PaymentSchemeChoice `xml:"PmtSchme"`
}

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

// SwissBCIdentifier ...
type SwissBCIdentifier string

// SwissSICIdentifier ...
type SwissSICIdentifier string

// UKDomesticSortCodeIdentifier ...
type UKDomesticSortCodeIdentifier string

// UPICIdentifier ...
type UPICIdentifier string

// Pain00200101 ...
type Pain00200101 struct {
	XMLName              xml.Name                            `xml:"pain.002.001.01"`
	GnlInf               *GeneralInformation1                `xml:"GnlInf"`
	OrgnlGrpRefInfAndSts *OriginalGroupReferenceInformation1 `xml:"OrgnlGrpRefInfAndSts"`
	OrgnlPmtInf          []*PaymentInformation9              `xml:"OrgnlPmtInf"`
}
