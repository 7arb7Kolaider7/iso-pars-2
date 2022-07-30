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

// BatchBookingIndicator ...
type BatchBookingIndicator bool

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

// ChargeBearer1Code ...
type ChargeBearer1Code string

// Cheque2 ...
type Cheque2 struct {
	ChqTp       string           `xml:"ChqTp"`
	ChqNb       string           `xml:"ChqNb"`
	ChqFr       *NameAndAddress3 `xml:"ChqFr"`
	DlvryMtd    string           `xml:"DlvryMtd"`
	DlvrTo      *NameAndAddress3 `xml:"DlvrTo"`
	InstrPrty   string           `xml:"InstrPrty"`
	ChqMtrtyDt  string           `xml:"ChqMtrtyDt"`
	FrmsCd      string           `xml:"FrmsCd"`
	MemoFld     string           `xml:"MemoFld"`
	RgnlClrZone string           `xml:"RgnlClrZone"`
}

// ChequeDelivery1Code ...
type ChequeDelivery1Code string

// ChequeType2Code ...
type ChequeType2Code string

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

// GenericPaymentTransaction3 ...
type GenericPaymentTransaction3 struct {
	PmtId           *PaymentIdentification                       `xml:"PmtId"`
	Purp            *PurposeChoice                               `xml:"Purp"`
	Amt             *AmountType1Choice                           `xml:"Amt"`
	ChqInstr        *Cheque2                                     `xml:"ChqInstr"`
	OrgtgPty        *PartyIdentification1                        `xml:"OrgtgPty"`
	IntrmyAgt1      *BranchAndFinancialInstitutionIdentification `xml:"IntrmyAgt1"`
	IntrmyAgt2      *BranchAndFinancialInstitutionIdentification `xml:"IntrmyAgt2"`
	Cdtr            *PartyIdentification1                        `xml:"Cdtr"`
	CdtrAcct        *CashAccount3                                `xml:"CdtrAcct"`
	CdtrCtryOfRes   string                                       `xml:"CdtrCtryOfRes"`
	FnlAgt          *BranchAndFinancialInstitutionIdentification `xml:"FnlAgt"`
	FnlAgtAcct      string                                       `xml:"FnlAgtAcct"`
	FnlPty          *PartyIdentification1                        `xml:"FnlPty"`
	ChrgBr          string                                       `xml:"ChrgBr"`
	XchgCtrctRef    string                                       `xml:"XchgCtrctRef"`
	RgltryRptg      []*StructuredRegulatoryReporting2            `xml:"RgltryRptg"`
	InstrForFnlAgt  *InstructionForFinalAgent                    `xml:"InstrForFnlAgt"`
	InstrForFrstAgt *InstructionForFirstAgent                    `xml:"InstrForFrstAgt"`
	RmtInf          []*RemittanceInformation3Choice              `xml:"RmtInf"`
}

// GermanBankleitzahlIdentifier ...
type GermanBankleitzahlIdentifier string

// GroupInformation1 ...
type GroupInformation1 struct {
	GrpId     string                                       `xml:"GrpId"`
	CreDtTm   string                                       `xml:"CreDtTm"`
	Authstn   []string                                     `xml:"Authstn"`
	CtrlSum   float64                                      `xml:"CtrlSum"`
	BtchBookg bool                                         `xml:"BtchBookg"`
	NbOfTxs   string                                       `xml:"NbOfTxs"`
	Grpg      bool                                         `xml:"Grpg"`
	InitgPty  *PartyIdentification1                        `xml:"InitgPty"`
	FwdgAgt   *BranchAndFinancialInstitutionIdentification `xml:"FwdgAgt"`
}

// GroupingIndicator ...
type GroupingIndicator bool

// HongKongBankIdentifier ...
type HongKongBankIdentifier string

// IBANIdentifier ...
type IBANIdentifier string

// ISODate ...
type ISODate string

// ISODateTime ...
type ISODateTime string

// Instruction3Code ...
type Instruction3Code string

// InstructionForFinalAgent ...
type InstructionForFinalAgent struct {
	Cd    []string `xml:"Cd"`
	Prtry string   `xml:"Prtry"`
}

// InstructionForFirstAgent ...
type InstructionForFirstAgent struct {
	RmtLctnMtd        string           `xml:"RmtLctnMtd"`
	RmtLctnElctrncAdr string           `xml:"RmtLctnElctrncAdr"`
	RmtLctnPstlAdr    *NameAndAddress3 `xml:"RmtLctnPstlAdr"`
	DbtPurp           string           `xml:"DbtPurp"`
	Prtry             string           `xml:"Prtry"`
	Tax               *TaxInformation1 `xml:"Tax"`
}

// IrishNSCIdentifier ...
type IrishNSCIdentifier string

// ItalianDomesticIdentifier ...
type ItalianDomesticIdentifier string

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

// Max3Text ...
type Max3Text string

// Max70Text ...
type Max70Text string

// NameAndAddress3 ...
type NameAndAddress3 struct {
	Nm  string          `xml:"Nm"`
	Adr *PostalAddress1 `xml:"Adr"`
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

// PaymentIdentification ...
type PaymentIdentification struct {
	InstrId    string `xml:"InstrId"`
	EndToEndId string `xml:"EndToEndId"`
	PmtRmtId   string `xml:"PmtRmtId"`
}

// PaymentInformation6 ...
type PaymentInformation6 struct {
	ReqdExctnDt     string                                       `xml:"ReqdExctnDt"`
	PmtMtdByFrstAgt string                                       `xml:"PmtMtdByFrstAgt"`
	CdtTrfTpId      *CreditTransferTypeIdentification            `xml:"CdtTrfTpId"`
	Dbtr            *PartyIdentification1                        `xml:"Dbtr"`
	DbtrCtryOfRes   string                                       `xml:"DbtrCtryOfRes"`
	DbtrAcct        *CashAccount3                                `xml:"DbtrAcct"`
	FrstAgt         *BranchAndFinancialInstitutionIdentification `xml:"FrstAgt"`
	ChrgsAcct       *CashAccount3                                `xml:"ChrgsAcct"`
	ChrgsAcctAgt    *BranchAndFinancialInstitutionIdentification `xml:"ChrgsAcctAgt"`
	PmtTx           []*GenericPaymentTransaction3                `xml:"PmtTx"`
}

// PaymentMethod1Code ...
type PaymentMethod1Code string

// PaymentPurpose1Code ...
type PaymentPurpose1Code string

// PaymentSchemeChoice ...
type PaymentSchemeChoice struct {
	Cd       string `xml:"Cd"`
	PrtryInf string `xml:"PrtryInf"`
}

// PercentageRate ...
type PercentageRate float64

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

// RemittanceLocationMethod1Code ...
type RemittanceLocationMethod1Code string

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

// StructuredRegulatoryReporting2 ...
type StructuredRegulatoryReporting2 struct {
	Cd  string             `xml:"Cd"`
	Amt *CurrencyAndAmount `xml:"Amt"`
	Inf string             `xml:"Inf"`
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

// TaxDetails ...
type TaxDetails struct {
	CertId string   `xml:"CertId"`
	TaxTp  *TaxType `xml:"TaxTp"`
}

// TaxInformation1 ...
type TaxInformation1 struct {
	CdtrTaxId       string             `xml:"CdtrTaxId"`
	CdtrTaxTp       string             `xml:"CdtrTaxTp"`
	DbtrTaxId       string             `xml:"DbtrTaxId"`
	TaxRefNb        string             `xml:"TaxRefNb"`
	TtlTaxblBaseAmt *CurrencyAndAmount `xml:"TtlTaxblBaseAmt"`
	TtlTaxAmt       *CurrencyAndAmount `xml:"TtlTaxAmt"`
	TaxTpInf        []*TaxDetails      `xml:"TaxTpInf"`
}

// TaxType ...
type TaxType struct {
	CtgyDesc     string             `xml:"CtgyDesc"`
	Rate         float64            `xml:"Rate"`
	TaxblBaseAmt *CurrencyAndAmount `xml:"TaxblBaseAmt"`
	Amt          *CurrencyAndAmount `xml:"Amt"`
}

// UKDomesticSortCodeIdentifier ...
type UKDomesticSortCodeIdentifier string

// UPICIdentifier ...
type UPICIdentifier string

// Pain00100101 ...
type Pain00100101 struct {
	XMLName xml.Name               `xml:"pain.001.001.01"`
	GrpHdr  *GroupInformation1     `xml:"GrpHdr"`
	PmtInf  []*PaymentInformation6 `xml:"PmtInf"`
}
