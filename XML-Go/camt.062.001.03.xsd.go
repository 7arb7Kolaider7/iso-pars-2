package schema

// Document ...
type Document *Document

// ActiveCurrencyAndAmountSimpleType ...
type ActiveCurrencyAndAmountSimpleType float64

// ActiveCurrencyAndAmount ...
type ActiveCurrencyAndAmount struct {
	CcyAttr string  `xml:"Ccy,attr"`
	Value   float64 `xml:",chardata"`
}

// ActiveCurrencyCode ...
type ActiveCurrencyCode string

// AddressType2Code ...
type AddressType2Code string

// AgreedRate2 ...
type AgreedRate2 struct {
	XchgRate float64 `xml:"XchgRate"`
	UnitCcy  string  `xml:"UnitCcy"`
	QtdCcy   string  `xml:"QtdCcy"`
}

// AnyBICIdentifier ...
type AnyBICIdentifier string

// BalanceStatus2 ...
type BalanceStatus2 struct {
	Bal *ActiveCurrencyAndAmount `xml:"Bal"`
}

// BaseOneRate ...
type BaseOneRate float64

// ClearingSystemIdentification2Choice ...
type ClearingSystemIdentification2Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// CountryCode ...
type CountryCode string

// CurrencyCode ...
type CurrencyCode string

// CurrencyFactors1 ...
type CurrencyFactors1 struct {
	Ccy         string       `xml:"Ccy"`
	ShrtPosLmt  float64      `xml:"ShrtPosLmt"`
	MinPayInAmt float64      `xml:"MinPayInAmt"`
	VoltlyMrgn  float64      `xml:"VoltlyMrgn"`
	Rate        *AgreedRate2 `xml:"Rate"`
}

// Entry2Code ...
type Entry2Code string

// Exact4AlphaNumericText ...
type Exact4AlphaNumericText string

// ExternalClearingSystemIdentification1Code ...
type ExternalClearingSystemIdentification1Code string

// ISODate ...
type ISODate string

// ISODateTime ...
type ISODateTime string

// ImpliedCurrencyAndAmount ...
type ImpliedCurrencyAndAmount float64

// LEIIdentifier ...
type LEIIdentifier string

// Max105Text ...
type Max105Text string

// Max16Text ...
type Max16Text string

// Max34Text ...
type Max34Text string

// Max350Text ...
type Max350Text string

// Max35Text ...
type Max35Text string

// Max70Text ...
type Max70Text string

// NameAndAddress8 ...
type NameAndAddress8 struct {
	Nm         string          `xml:"Nm"`
	Adr        *PostalAddress1 `xml:"Adr"`
	AltrntvIdr []string        `xml:"AltrntvIdr"`
}

// PartyIdentification44 ...
type PartyIdentification44 struct {
	AnyBIC     string   `xml:"AnyBIC"`
	AltrntvIdr []string `xml:"AltrntvIdr"`
}

// PartyIdentification59 ...
type PartyIdentification59 struct {
	PtyNm      string                               `xml:"PtyNm"`
	AnyBIC     *PartyIdentification44               `xml:"AnyBIC"`
	AcctNb     string                               `xml:"AcctNb"`
	Adr        string                               `xml:"Adr"`
	ClrSysId   *ClearingSystemIdentification2Choice `xml:"ClrSysId"`
	LglNttyIdr string                               `xml:"LglNttyIdr"`
}

// PartyIdentification73Choice ...
type PartyIdentification73Choice struct {
	NmAndAdr *NameAndAddress8       `xml:"NmAndAdr"`
	AnyBIC   *PartyIdentification44 `xml:"AnyBIC"`
	PtyId    *PartyIdentification59 `xml:"PtyId"`
}

// PayInFactors1 ...
type PayInFactors1 struct {
	AggtShrtPosLmt *ActiveCurrencyAndAmount `xml:"AggtShrtPosLmt"`
	CcyFctrs       []*CurrencyFactors1      `xml:"CcyFctrs"`
}

// PayInScheduleItems1 ...
type PayInScheduleItems1 struct {
	Amt  *ActiveCurrencyAndAmount `xml:"Amt"`
	Ddln string                   `xml:"Ddln"`
}

// PayInScheduleV03 ...
type PayInScheduleV03 struct {
	PtyId            *PartyIdentification73Choice `xml:"PtyId"`
	RptData          *ReportData4                 `xml:"RptData"`
	PayInSchdlLngBal []*BalanceStatus2            `xml:"PayInSchdlLngBal"`
	PayInSchdlItm    []*PayInScheduleItems1       `xml:"PayInSchdlItm"`
	PayInFctrs       *PayInFactors1               `xml:"PayInFctrs"`
	SplmtryData      []*SupplementaryData1        `xml:"SplmtryData"`
}

// PercentageRate ...
type PercentageRate float64

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

// ReportData4 ...
type ReportData4 struct {
	MsgId       string `xml:"MsgId"`
	ValDt       string `xml:"ValDt"`
	DtAndTmStmp string `xml:"DtAndTmStmp"`
	Tp          string `xml:"Tp"`
	SchdlTp     string `xml:"SchdlTp"`
	SttlmSsnIdr string `xml:"SttlmSsnIdr"`
}

// SupplementaryData1 ...
type SupplementaryData1 struct {
	PlcAndNm string                      `xml:"PlcAndNm"`
	Envlp    *SupplementaryDataEnvelope1 `xml:"Envlp"`
}

// SupplementaryDataEnvelope1 ...
type SupplementaryDataEnvelope1 struct {
}
