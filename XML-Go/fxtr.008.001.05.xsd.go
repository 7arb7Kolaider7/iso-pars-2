package schema

// Document ...
type Document *Document

// AddressType2Code ...
type AddressType2Code string

// AllocationIndicator1Code ...
type AllocationIndicator1Code string

// AnyBICIdentifier ...
type AnyBICIdentifier string

// ClearingBrokerIdentification1 ...
type ClearingBrokerIdentification1 struct {
	SdInd     string `xml:"SdInd"`
	ClrBrkrId string `xml:"ClrBrkrId"`
}

// ClearingSystemIdentification2Choice ...
type ClearingSystemIdentification2Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// CollateralisationIndicator1Code ...
type CollateralisationIndicator1Code string

// CorporateSectorIdentifier1Code ...
type CorporateSectorIdentifier1Code string

// CounterpartySideTransactionReporting1 ...
type CounterpartySideTransactionReporting1 struct {
	RptgJursdctn     string                          `xml:"RptgJursdctn"`
	RptgPty          *PartyIdentification73Choice    `xml:"RptgPty"`
	CtrPtySdUnqTxIdr []*UniqueTransactionIdentifier2 `xml:"CtrPtySdUnqTxIdr"`
}

// CountryCode ...
type CountryCode string

// DateAndDateTimeChoice ...
type DateAndDateTimeChoice struct {
	Dt   string `xml:"Dt"`
	DtTm string `xml:"DtTm"`
}

// Exact42Text ...
type Exact42Text string

// Exact4AlphaNumericText ...
type Exact4AlphaNumericText string

// ExternalClearingSystemIdentification1Code ...
type ExternalClearingSystemIdentification1Code string

// ForeignExchangeTradeStatusNotificationV05 ...
type ForeignExchangeTradeStatusNotificationV05 struct {
	TradData    *TradeData7           `xml:"TradData"`
	RgltryRptg  *RegulatoryReporting4 `xml:"RgltryRptg"`
	SplmtryData []*SupplementaryData1 `xml:"SplmtryData"`
}

// ISODate ...
type ISODate string

// ISODateTime ...
type ISODateTime string

// LEIIdentifier ...
type LEIIdentifier string

// Max105Text ...
type Max105Text string

// Max10Text ...
type Max10Text string

// Max16Text ...
type Max16Text string

// Max20Text ...
type Max20Text string

// Max210Text ...
type Max210Text string

// Max34Text ...
type Max34Text string

// Max350Text ...
type Max350Text string

// Max35Text ...
type Max35Text string

// Max52Text ...
type Max52Text string

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

// RegulatoryReporting4 ...
type RegulatoryReporting4 struct {
	TradgSdTxRptg          []*TradingSideTransactionReporting1      `xml:"TradgSdTxRptg"`
	CtrPtySdTxRptg         []*CounterpartySideTransactionReporting1 `xml:"CtrPtySdTxRptg"`
	CntrlCtrPtyClrHs       *PartyIdentification73Choice             `xml:"CntrlCtrPtyClrHs"`
	ClrBrkr                *PartyIdentification73Choice             `xml:"ClrBrkr"`
	ClrXcptnPty            *PartyIdentification73Choice             `xml:"ClrXcptnPty"`
	ClrBrkrId              *ClearingBrokerIdentification1           `xml:"ClrBrkrId"`
	ClrThrshldInd          bool                                     `xml:"ClrThrshldInd"`
	ClrdPdctId             string                                   `xml:"ClrdPdctId"`
	UndrlygPdctIdr         string                                   `xml:"UndrlygPdctIdr"`
	AllcnInd               string                                   `xml:"AllcnInd"`
	CollstnInd             string                                   `xml:"CollstnInd"`
	ExctnVn                string                                   `xml:"ExctnVn"`
	ExctnTmstmp            *DateAndDateTimeChoice                   `xml:"ExctnTmstmp"`
	NonStdFlg              bool                                     `xml:"NonStdFlg"`
	LkSwpId                string                                   `xml:"LkSwpId"`
	FinNtrOfTheCtrPtyInd   bool                                     `xml:"FinNtrOfTheCtrPtyInd"`
	CollPrtflInd           bool                                     `xml:"CollPrtflInd"`
	CollPrtflCd            string                                   `xml:"CollPrtflCd"`
	PrtflCmprssnInd        bool                                     `xml:"PrtflCmprssnInd"`
	CorpSctrInd            string                                   `xml:"CorpSctrInd"`
	TradWthNonEEACtrPtyInd bool                                     `xml:"TradWthNonEEACtrPtyInd"`
	NtrgrpTradInd          bool                                     `xml:"NtrgrpTradInd"`
	ComrclOrTrsrFincgInd   bool                                     `xml:"ComrclOrTrsrFincgInd"`
	AddtlRptgInf           string                                   `xml:"AddtlRptgInf"`
}

// SideIndicator1Code ...
type SideIndicator1Code string

// Status13Choice ...
type Status13Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// Status6Choice ...
type Status6Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// StatusAndSubStatus1 ...
type StatusAndSubStatus1 struct {
	StsCd    *Status13Choice `xml:"StsCd"`
	SubStsCd string          `xml:"SubStsCd"`
}

// StatusSubType1Code ...
type StatusSubType1Code string

// SupplementaryData1 ...
type SupplementaryData1 struct {
	PlcAndNm string                      `xml:"PlcAndNm"`
	Envlp    *SupplementaryDataEnvelope1 `xml:"Envlp"`
}

// SupplementaryDataEnvelope1 ...
type SupplementaryDataEnvelope1 struct {
}

// TradeData7 ...
type TradeData7 struct {
	MsgId              string               `xml:"MsgId"`
	OrgtrRef           string               `xml:"OrgtrRef"`
	MtchgSysUnqRef     string               `xml:"MtchgSysUnqRef"`
	MtchgSysMtchgRef   string               `xml:"MtchgSysMtchgRef"`
	MtchgSysMtchdSdRef string               `xml:"MtchgSysMtchdSdRef"`
	StsOrgtr           string               `xml:"StsOrgtr"`
	CurSts             *StatusAndSubStatus1 `xml:"CurSts"`
	CurStsSubTp        string               `xml:"CurStsSubTp"`
	CurStsDtTm         string               `xml:"CurStsDtTm"`
	PrvsSts            *Status6Choice       `xml:"PrvsSts"`
	PrvsStsSubTp       string               `xml:"PrvsStsSubTp"`
	PrvsStsDtTm        string               `xml:"PrvsStsDtTm"`
	PdctTp             string               `xml:"PdctTp"`
	SttlmSsnIdr        string               `xml:"SttlmSsnIdr"`
	SpltTradInd        bool                 `xml:"SpltTradInd"`
}

// TradeStatus4Code ...
type TradeStatus4Code string

// TradeStatus5Code ...
type TradeStatus5Code string

// TradingSideTransactionReporting1 ...
type TradingSideTransactionReporting1 struct {
	RptgJursdctn    string                          `xml:"RptgJursdctn"`
	RptgPty         *PartyIdentification73Choice    `xml:"RptgPty"`
	TradgSdUnqTxIdr []*UniqueTransactionIdentifier2 `xml:"TradgSdUnqTxIdr"`
}

// UnderlyingProductIdentifier1Code ...
type UnderlyingProductIdentifier1Code string

// UniqueTransactionIdentifier2 ...
type UniqueTransactionIdentifier2 struct {
	UnqTxIdr    string   `xml:"UnqTxIdr"`
	PrrUnqTxIdr []string `xml:"PrrUnqTxIdr"`
}

// YesNoIndicator ...
type YesNoIndicator bool
