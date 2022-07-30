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

// AgreedRate1 ...
type AgreedRate1 struct {
	XchgRate float64 `xml:"XchgRate"`
	UnitCcy  string  `xml:"UnitCcy"`
	QtdCcy   string  `xml:"QtdCcy"`
}

// AllocationIndicator1Code ...
type AllocationIndicator1Code string

// AmountsAndValueDate1 ...
type AmountsAndValueDate1 struct {
	TradgSdBuyAmt  *ActiveOrHistoricCurrencyAndAmount `xml:"TradgSdBuyAmt"`
	TradgSdSellAmt *ActiveOrHistoricCurrencyAndAmount `xml:"TradgSdSellAmt"`
	SttlmDt        string                             `xml:"SttlmDt"`
}

// AnyBICIdentifier ...
type AnyBICIdentifier string

// BaseOneRate ...
type BaseOneRate float64

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

// ContactInformation1 ...
type ContactInformation1 struct {
	Nm       string `xml:"Nm"`
	FaxNb    string `xml:"FaxNb"`
	TelNb    string `xml:"TelNb"`
	EmailAdr string `xml:"EmailAdr"`
}

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

// CurrencyCode ...
type CurrencyCode string

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

// ForeignExchangeTradeInstructionV03 ...
type ForeignExchangeTradeInstructionV03 struct {
	TradInf             *TradeAgreement10          `xml:"TradInf"`
	TradgSdId           *TradePartyIdentification6 `xml:"TradgSdId"`
	CtrPtySdId          *TradePartyIdentification6 `xml:"CtrPtySdId"`
	TradAmts            *AmountsAndValueDate1      `xml:"TradAmts"`
	AgrdRate            *AgreedRate1               `xml:"AgrdRate"`
	TradgSdSttlmInstrs  *SettlementParties29       `xml:"TradgSdSttlmInstrs"`
	CtrPtySdSttlmInstrs *SettlementParties29       `xml:"CtrPtySdSttlmInstrs"`
	OptnlGnlInf         *GeneralInformation4       `xml:"OptnlGnlInf"`
	RgltryRptg          *RegulatoryReporting4      `xml:"RgltryRptg"`
	SplmtryData         []*SupplementaryData1      `xml:"SplmtryData"`
}

// FundIdentification4 ...
type FundIdentification4 struct {
	FndId         *PartyIdentification60       `xml:"FndId"`
	AcctIdWthCtdn string                       `xml:"AcctIdWthCtdn"`
	CtdnId        *PartyIdentification73Choice `xml:"CtdnId"`
}

// GeneralInformation4 ...
type GeneralInformation4 struct {
	BlckInd            bool                         `xml:"BlckInd"`
	RltdTradRef        string                       `xml:"RltdTradRef"`
	DealgMtd           string                       `xml:"DealgMtd"`
	BrkrId             *PartyIdentification73Choice `xml:"BrkrId"`
	CtrPtyRef          string                       `xml:"CtrPtyRef"`
	BrkrsComssn        *ActiveCurrencyAndAmount     `xml:"BrkrsComssn"`
	SndrToRcvrInf      string                       `xml:"SndrToRcvrInf"`
	DealgBrnchTradgSd  *PartyIdentification73Choice `xml:"DealgBrnchTradgSd"`
	DealgBrnchCtrPtySd *PartyIdentification73Choice `xml:"DealgBrnchCtrPtySd"`
	CtctInf            *ContactInformation1         `xml:"CtctInf"`
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

// Max256Text ...
type Max256Text string

// Max34Text ...
type Max34Text string

// Max350Text ...
type Max350Text string

// Max35Text ...
type Max35Text string

// Max4Text ...
type Max4Text string

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

// PartyIdentification60 ...
type PartyIdentification60 struct {
	FndId      string           `xml:"FndId"`
	NmAndAdr   *NameAndAddress8 `xml:"NmAndAdr"`
	LglNttyIdr string           `xml:"LglNttyIdr"`
}

// PartyIdentification73Choice ...
type PartyIdentification73Choice struct {
	NmAndAdr *NameAndAddress8       `xml:"NmAndAdr"`
	AnyBIC   *PartyIdentification44 `xml:"AnyBIC"`
	PtyId    *PartyIdentification59 `xml:"PtyId"`
}

// PhoneNumber ...
type PhoneNumber string

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

// SettlementParties29 ...
type SettlementParties29 struct {
	DlvryAgt    *PartyIdentification73Choice `xml:"DlvryAgt"`
	Intrmy      *PartyIdentification73Choice `xml:"Intrmy"`
	RcvgAgt     *PartyIdentification73Choice `xml:"RcvgAgt"`
	BnfcryInstn *PartyIdentification73Choice `xml:"BnfcryInstn"`
}

// SideIndicator1Code ...
type SideIndicator1Code string

// SupplementaryData1 ...
type SupplementaryData1 struct {
	PlcAndNm string                      `xml:"PlcAndNm"`
	Envlp    *SupplementaryDataEnvelope1 `xml:"Envlp"`
}

// SupplementaryDataEnvelope1 ...
type SupplementaryDataEnvelope1 struct {
}

// TradeAgreement10 ...
type TradeAgreement10 struct {
	TradDt        string `xml:"TradDt"`
	OrgtrRef      string `xml:"OrgtrRef"`
	CmonRef       string `xml:"CmonRef"`
	OprTp         string `xml:"OprTp"`
	OprScp        string `xml:"OprScp"`
	SttlmSsnIdr   string `xml:"SttlmSsnIdr"`
	PmtVrssPmtInd bool   `xml:"PmtVrssPmtInd"`
}

// TradePartyIdentification6 ...
type TradePartyIdentification6 struct {
	SubmitgPty *PartyIdentification73Choice `xml:"SubmitgPty"`
	TradPty    *PartyIdentification73Choice `xml:"TradPty"`
	FndId      []*FundIdentification4       `xml:"FndId"`
}

// Trading1MethodCode ...
type Trading1MethodCode string

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
