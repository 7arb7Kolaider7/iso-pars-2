package schema

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

// DatePeriod2 ...
type DatePeriod2 struct {
	FrDt string `xml:"FrDt"`
	ToDt string `xml:"ToDt"`
}

// DatePeriod2Choice ...
type DatePeriod2Choice struct {
	FrDt   string       `xml:"FrDt"`
	ToDt   string       `xml:"ToDt"`
	FrToDt *DatePeriod2 `xml:"FrToDt"`
}

// Exact4AlphaNumericText ...
type Exact4AlphaNumericText string

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

// GetStandingOrderV03 ...
type GetStandingOrderV03 struct {
	MsgHdr        *MessageHeader4       `xml:"MsgHdr"`
	StgOrdrQryDef *StandingOrderQuery3  `xml:"StgOrdrQryDef"`
	SplmtryData   []*SupplementaryData1 `xml:"SplmtryData"`
}

// IBAN2007Identifier ...
type IBAN2007Identifier string

// ISODate ...
type ISODate string

// ISODateTime ...
type ISODateTime string

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

// MessageHeader4 ...
type MessageHeader4 struct {
	MsgId   string              `xml:"MsgId"`
	CreDtTm string              `xml:"CreDtTm"`
	ReqTp   *RequestType3Choice `xml:"ReqTp"`
}

// Number ...
type Number float64

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

// QueryType2Code ...
type QueryType2Code string

// RequestType3Choice ...
type RequestType3Choice struct {
	Cd    string                  `xml:"Cd"`
	Prtry *GenericIdentification1 `xml:"Prtry"`
}

// RequestedIndicator ...
type RequestedIndicator bool

// StandingOrderCriteria3 ...
type StandingOrderCriteria3 struct {
	NewQryNm string                          `xml:"NewQryNm"`
	SchCrit  []*StandingOrderSearchCriteria3 `xml:"SchCrit"`
	RtrCrit  *StandingOrderReturnCriteria1   `xml:"RtrCrit"`
}

// StandingOrderCriteria3Choice ...
type StandingOrderCriteria3Choice struct {
	QryNm   string                  `xml:"QryNm"`
	NewCrit *StandingOrderCriteria3 `xml:"NewCrit"`
}

// StandingOrderQuery3 ...
type StandingOrderQuery3 struct {
	QryTp       string                        `xml:"QryTp"`
	StgOrdrCrit *StandingOrderCriteria3Choice `xml:"StgOrdrCrit"`
}

// StandingOrderQueryType1Code ...
type StandingOrderQueryType1Code string

// StandingOrderReturnCriteria1 ...
type StandingOrderReturnCriteria1 struct {
	StgOrdrIdInd    bool `xml:"StgOrdrIdInd"`
	TpInd           bool `xml:"TpInd"`
	SysMmbInd       bool `xml:"SysMmbInd"`
	RspnsblPtyInd   bool `xml:"RspnsblPtyInd"`
	CcyInd          bool `xml:"CcyInd"`
	DbtrAcctInd     bool `xml:"DbtrAcctInd"`
	CdtrAcctInd     bool `xml:"CdtrAcctInd"`
	AssoctdPoolAcct bool `xml:"AssoctdPoolAcct"`
	FrqcyInd        bool `xml:"FrqcyInd"`
	ExctnTpInd      bool `xml:"ExctnTpInd"`
	VldtyFrInd      bool `xml:"VldtyFrInd"`
	VldToInd        bool `xml:"VldToInd"`
	LkSetIdInd      bool `xml:"LkSetIdInd"`
	LkSetOrdrIdInd  bool `xml:"LkSetOrdrIdInd"`
	LkSetOrdrSeqInd bool `xml:"LkSetOrdrSeqInd"`
	TtlAmtInd       bool `xml:"TtlAmtInd"`
	ZeroSweepInd    bool `xml:"ZeroSweepInd"`
}

// StandingOrderSearchCriteria3 ...
type StandingOrderSearchCriteria3 struct {
	KeyAttrbtsInd   bool                                          `xml:"KeyAttrbtsInd"`
	StgOrdrId       string                                        `xml:"StgOrdrId"`
	Tp              *StandingOrderType1Choice                     `xml:"Tp"`
	Acct            *CashAccount38                                `xml:"Acct"`
	Ccy             string                                        `xml:"Ccy"`
	VldtyPrd        *DatePeriod2Choice                            `xml:"VldtyPrd"`
	SysMmb          *BranchAndFinancialInstitutionIdentification6 `xml:"SysMmb"`
	RspnsblPty      *BranchAndFinancialInstitutionIdentification6 `xml:"RspnsblPty"`
	AssoctdPoolAcct *AccountIdentification4Choice                 `xml:"AssoctdPoolAcct"`
	LkSetId         string                                        `xml:"LkSetId"`
	LkSetOrdrId     string                                        `xml:"LkSetOrdrId"`
	LkSetOrdrSeq    float64                                       `xml:"LkSetOrdrSeq"`
	ZeroSweepInd    bool                                          `xml:"ZeroSweepInd"`
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

// TrueFalseIndicator ...
type TrueFalseIndicator bool
