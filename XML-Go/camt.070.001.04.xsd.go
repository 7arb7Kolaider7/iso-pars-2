package schema

import (
	"time"
)

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

// ActiveOrHistoricCurrencyCode ...
type ActiveOrHistoricCurrencyCode string

// AddressType2Code ...
type AddressType2Code string

// AddressType3Choice ...
type AddressType3Choice struct {
	Cd    string                   `xml:"Cd"`
	Prtry *GenericIdentification30 `xml:"Prtry"`
}

// Amount2Choice ...
type Amount2Choice struct {
	AmtWthtCcy float64                  `xml:"AmtWthtCcy"`
	AmtWthCcy  *ActiveCurrencyAndAmount `xml:"AmtWthCcy"`
}

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

// CashAccount38 ...
type CashAccount38 struct {
	Id   *AccountIdentification4Choice `xml:"Id"`
	Tp   *CashAccountType2Choice       `xml:"Tp"`
	Ccy  string                        `xml:"Ccy"`
	Nm   string                        `xml:"Nm"`
	Prxy *ProxyAccountIdentification1  `xml:"Prxy"`
}

// CashAccountType2Choice ...
type CashAccountType2Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// ClearingSystemIdentification2Choice ...
type ClearingSystemIdentification2Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// ClearingSystemMemberIdentification2 ...
type ClearingSystemMemberIdentification2 struct {
	ClrSysId *ClearingSystemIdentification2Choice `xml:"ClrSysId"`
	MmbId    string                               `xml:"MmbId"`
}

// CountryCode ...
type CountryCode string

// CreditDebitCode ...
type CreditDebitCode string

// DatePeriodDetails1 ...
type DatePeriodDetails1 struct {
	FrDt string `xml:"FrDt"`
	ToDt string `xml:"ToDt"`
}

// ErrorHandling3Choice ...
type ErrorHandling3Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// ErrorHandling5 ...
type ErrorHandling5 struct {
	Err  *ErrorHandling3Choice `xml:"Err"`
	Desc string                `xml:"Desc"`
}

// EventType1Choice ...
type EventType1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// Exact4AlphaNumericText ...
type Exact4AlphaNumericText string

// ExecutionType1Choice ...
type ExecutionType1Choice struct {
	Tm  time.Time         `xml:"Tm"`
	Evt *EventType1Choice `xml:"Evt"`
}

// ExternalAccountIdentification1Code ...
type ExternalAccountIdentification1Code string

// ExternalCashAccountType1Code ...
type ExternalCashAccountType1Code string

// ExternalClearingSystemIdentification1Code ...
type ExternalClearingSystemIdentification1Code string

// ExternalFinancialInstitutionIdentification1Code ...
type ExternalFinancialInstitutionIdentification1Code string

// ExternalProxyAccountType1Code ...
type ExternalProxyAccountType1Code string

// ExternalSystemErrorHandling1Code ...
type ExternalSystemErrorHandling1Code string

// ExternalSystemEventType1Code ...
type ExternalSystemEventType1Code string

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

// Frequency2Code ...
type Frequency2Code string

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

// IBAN2007Identifier ...
type IBAN2007Identifier string

// ISODate ...
type ISODate string

// ISODateTime ...
type ISODateTime string

// ISOTime ...
type ISOTime time.Time

// ImpliedCurrencyAndAmount ...
type ImpliedCurrencyAndAmount float64

// LEIIdentifier ...
type LEIIdentifier string

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

// Max70Text ...
type Max70Text string

// MessageHeader6 ...
type MessageHeader6 struct {
	MsgId       string                  `xml:"MsgId"`
	CreDtTm     string                  `xml:"CreDtTm"`
	OrgnlBizQry *OriginalBusinessQuery1 `xml:"OrgnlBizQry"`
	QryNm       string                  `xml:"QryNm"`
	ReqTp       *RequestType3Choice     `xml:"ReqTp"`
}

// Number ...
type Number float64

// OriginalBusinessQuery1 ...
type OriginalBusinessQuery1 struct {
	MsgId   string `xml:"MsgId"`
	MsgNmId string `xml:"MsgNmId"`
	CreDtTm string `xml:"CreDtTm"`
}

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

// ProxyAccountIdentification1 ...
type ProxyAccountIdentification1 struct {
	Tp *ProxyAccountType1Choice `xml:"Tp"`
	Id string                   `xml:"Id"`
}

// ProxyAccountType1Choice ...
type ProxyAccountType1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// RequestType3Choice ...
type RequestType3Choice struct {
	Cd    string                  `xml:"Cd"`
	Prtry *GenericIdentification1 `xml:"Prtry"`
}

// ReturnStandingOrderV04 ...
type ReturnStandingOrderV04 struct {
	MsgHdr      *MessageHeader6              `xml:"MsgHdr"`
	RptOrErr    *StandingOrderOrError5Choice `xml:"RptOrErr"`
	SplmtryData []*SupplementaryData1        `xml:"SplmtryData"`
}

// StandingOrder6 ...
type StandingOrder6 struct {
	Amt             *Amount2Choice                                `xml:"Amt"`
	CdtDbtInd       string                                        `xml:"CdtDbtInd"`
	Ccy             string                                        `xml:"Ccy"`
	Tp              *StandingOrderType1Choice                     `xml:"Tp"`
	AssoctdPoolAcct *AccountIdentification4Choice                 `xml:"AssoctdPoolAcct"`
	Ref             string                                        `xml:"Ref"`
	Frqcy           string                                        `xml:"Frqcy"`
	VldtyPrd        *DatePeriodDetails1                           `xml:"VldtyPrd"`
	SysMmb          *BranchAndFinancialInstitutionIdentification6 `xml:"SysMmb"`
	RspnsblPty      *BranchAndFinancialInstitutionIdentification6 `xml:"RspnsblPty"`
	LkSetId         string                                        `xml:"LkSetId"`
	LkSetOrdrId     string                                        `xml:"LkSetOrdrId"`
	LkSetOrdrSeq    float64                                       `xml:"LkSetOrdrSeq"`
	ExctnTp         *ExecutionType1Choice                         `xml:"ExctnTp"`
	Cdtr            *BranchAndFinancialInstitutionIdentification6 `xml:"Cdtr"`
	CdtrAcct        *CashAccount38                                `xml:"CdtrAcct"`
	Dbtr            *BranchAndFinancialInstitutionIdentification6 `xml:"Dbtr"`
	DbtrAcct        *CashAccount38                                `xml:"DbtrAcct"`
	TtlsPerStgOrdr  *StandingOrderTotalAmount1                    `xml:"TtlsPerStgOrdr"`
	ZeroSweepInd    bool                                          `xml:"ZeroSweepInd"`
}

// StandingOrderIdentification4 ...
type StandingOrderIdentification4 struct {
	Id       string                                        `xml:"Id"`
	Acct     *CashAccount38                                `xml:"Acct"`
	AcctOwnr *BranchAndFinancialInstitutionIdentification6 `xml:"AcctOwnr"`
}

// StandingOrderOrError5Choice ...
type StandingOrderOrError5Choice struct {
	Rpt     []*StandingOrderReport1 `xml:"Rpt"`
	OprlErr []*ErrorHandling5       `xml:"OprlErr"`
}

// StandingOrderOrError6Choice ...
type StandingOrderOrError6Choice struct {
	StgOrdr *StandingOrder6   `xml:"StgOrdr"`
	BizErr  []*ErrorHandling5 `xml:"BizErr"`
}

// StandingOrderQueryType1Code ...
type StandingOrderQueryType1Code string

// StandingOrderReport1 ...
type StandingOrderReport1 struct {
	StgOrdrId    *StandingOrderIdentification4 `xml:"StgOrdrId"`
	StgOrdrOrErr *StandingOrderOrError6Choice  `xml:"StgOrdrOrErr"`
}

// StandingOrderTotalAmount1 ...
type StandingOrderTotalAmount1 struct {
	SetPrdfndOrdr *TotalAmountAndCurrency1 `xml:"SetPrdfndOrdr"`
	PdgPrdfndOrdr *TotalAmountAndCurrency1 `xml:"PdgPrdfndOrdr"`
	SetStgOrdr    *TotalAmountAndCurrency1 `xml:"SetStgOrdr"`
	PdgStgOrdr    *TotalAmountAndCurrency1 `xml:"PdgStgOrdr"`
}

// StandingOrderType1Choice ...
type StandingOrderType1Choice struct {
	Cd    string                  `xml:"Cd"`
	Prtry *GenericIdentification1 `xml:"Prtry"`
}

// StandingOrderType1Code ...
type StandingOrderType1Code string

// SupplementaryData1 ...
type SupplementaryData1 struct {
	PlcAndNm string                      `xml:"PlcAndNm"`
	Envlp    *SupplementaryDataEnvelope1 `xml:"Envlp"`
}

// SupplementaryDataEnvelope1 ...
type SupplementaryDataEnvelope1 struct {
}

// TotalAmountAndCurrency1 ...
type TotalAmountAndCurrency1 struct {
	TtlAmt    float64 `xml:"TtlAmt"`
	CdtDbtInd string  `xml:"CdtDbtInd"`
	Ccy       string  `xml:"Ccy"`
}

// TrueFalseIndicator ...
type TrueFalseIndicator bool
