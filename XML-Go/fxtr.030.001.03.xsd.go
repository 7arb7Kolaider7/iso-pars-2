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

// ForeignExchangeTradeBulkStatusNotificationV03 ...
type ForeignExchangeTradeBulkStatusNotificationV03 struct {
	StsDtls     *TradeData10          `xml:"StsDtls"`
	TradData    []*TradeData11        `xml:"TradData"`
	MsgPgntn    *Pagination           `xml:"MsgPgntn"`
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

// Max5NumericText ...
type Max5NumericText string

// Max70Text ...
type Max70Text string

// NameAndAddress8 ...
type NameAndAddress8 struct {
	Nm         string          `xml:"Nm"`
	Adr        *PostalAddress1 `xml:"Adr"`
	AltrntvIdr []string        `xml:"AltrntvIdr"`
}

// Pagination ...
type Pagination struct {
	PgNb      string `xml:"PgNb"`
	LastPgInd bool   `xml:"LastPgInd"`
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

// Status5Choice ...
type Status5Choice struct {
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

// TradeData10 ...
type TradeData10 struct {
	MsgId        string               `xml:"MsgId"`
	StsOrgtr     string               `xml:"StsOrgtr"`
	CurSts       *StatusAndSubStatus1 `xml:"CurSts"`
	CurStsSubTp  string               `xml:"CurStsSubTp"`
	CurStsDtTm   string               `xml:"CurStsDtTm"`
	PrvsSts      *Status5Choice       `xml:"PrvsSts"`
	PrvsStsSubTp string               `xml:"PrvsStsSubTp"`
	PdctTp       string               `xml:"PdctTp"`
}

// TradeData11 ...
type TradeData11 struct {
	OrgtrRef           string                `xml:"OrgtrRef"`
	MtchgSysUnqRef     string                `xml:"MtchgSysUnqRef"`
	MtchgSysMtchgRef   string                `xml:"MtchgSysMtchgRef"`
	MtchgSysMtchdSdRef string                `xml:"MtchgSysMtchdSdRef"`
	CurSttlmDt         string                `xml:"CurSttlmDt"`
	NewSttlmDt         string                `xml:"NewSttlmDt"`
	CurStsDtTm         string                `xml:"CurStsDtTm"`
	PdctTp             string                `xml:"PdctTp"`
	SttlmSsnIdr        string                `xml:"SttlmSsnIdr"`
	RgltryRptg         *RegulatoryReporting4 `xml:"RgltryRptg"`
}

// TradeStatus3Code ...
type TradeStatus3Code string

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
