package schema

// Document ...
type Document *Document

// ActiveOrHistoricCurrencyAndAmountSimpleType ...
type ActiveOrHistoricCurrencyAndAmountSimpleType float64

// ActiveOrHistoricCurrencyAndAmount ...
type ActiveOrHistoricCurrencyAndAmount struct {
	CcyAttr string  `xml:"Ccy,attr"`
	Value   float64 `xml:",chardata"`
}

// ActiveOrHistoricCurrencyCode ...
type ActiveOrHistoricCurrencyCode string

// AddressType2Code ...
type AddressType2Code string

// AnyBICIdentifier ...
type AnyBICIdentifier string

// CallIn1Code ...
type CallIn1Code string

// ClearingSystemIdentification2Choice ...
type ClearingSystemIdentification2Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// CountryCode ...
type CountryCode string

// Exact4AlphaNumericText ...
type Exact4AlphaNumericText string

// ExternalClearingSystemIdentification1Code ...
type ExternalClearingSystemIdentification1Code string

// ISODate ...
type ISODate string

// ISODateTime ...
type ISODateTime string

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

// PayInCallItem ...
type PayInCallItem struct {
	Amt *ActiveOrHistoricCurrencyAndAmount `xml:"Amt"`
}

// PayInCallV02 ...
type PayInCallV02 struct {
	PtyId       *PartyIdentification73Choice `xml:"PtyId"`
	RptData     *ReportData5                 `xml:"RptData"`
	SttlmSsnIdr string                       `xml:"SttlmSsnIdr"`
	SplmtryData []*SupplementaryData1        `xml:"SplmtryData"`
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

// ReportData5 ...
type ReportData5 struct {
	MsgId        string           `xml:"MsgId"`
	ValDt        string           `xml:"ValDt"`
	DtAndTmStmp  string           `xml:"DtAndTmStmp"`
	Tp           string           `xml:"Tp"`
	PayInCallAmt []*PayInCallItem `xml:"PayInCallAmt"`
	SttlmSsnIdr  string           `xml:"SttlmSsnIdr"`
	AcctVal      *Value           `xml:"AcctVal"`
}

// SupplementaryData1 ...
type SupplementaryData1 struct {
	PlcAndNm string                      `xml:"PlcAndNm"`
	Envlp    *SupplementaryDataEnvelope1 `xml:"Envlp"`
}

// SupplementaryDataEnvelope1 ...
type SupplementaryDataEnvelope1 struct {
}

// Value ...
type Value struct {
	BaseCcyItm  *ActiveOrHistoricCurrencyAndAmount   `xml:"BaseCcyItm"`
	AltrnCcyItm []*ActiveOrHistoricCurrencyAndAmount `xml:"AltrnCcyItm"`
}
