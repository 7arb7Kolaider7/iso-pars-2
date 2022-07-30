package schema

// Document ...
type Document *Document

// ActiveCurrencyAnd13DecimalAmountSimpleType ...
type ActiveCurrencyAnd13DecimalAmountSimpleType float64

// ActiveCurrencyAnd13DecimalAmount ...
type ActiveCurrencyAnd13DecimalAmount struct {
	CcyAttr string  `xml:"Ccy,attr"`
	Value   float64 `xml:",chardata"`
}

// ActiveCurrencyCode ...
type ActiveCurrencyCode string

// ActiveOrHistoricCurrencyAnd13DecimalAmountSimpleType ...
type ActiveOrHistoricCurrencyAnd13DecimalAmountSimpleType float64

// ActiveOrHistoricCurrencyAnd13DecimalAmount ...
type ActiveOrHistoricCurrencyAnd13DecimalAmount struct {
	CcyAttr string  `xml:"Ccy,attr"`
	Value   float64 `xml:",chardata"`
}

// ActiveOrHistoricCurrencyAndAmountSimpleType ...
type ActiveOrHistoricCurrencyAndAmountSimpleType float64

// ActiveOrHistoricCurrencyAndAmount ...
type ActiveOrHistoricCurrencyAndAmount struct {
	CcyAttr string  `xml:"Ccy,attr"`
	Value   float64 `xml:",chardata"`
}

// ActiveOrHistoricCurrencyCode ...
type ActiveOrHistoricCurrencyCode string

// AdditionalParameters1 ...
type AdditionalParameters1 struct {
	Ctry    string `xml:"Ctry"`
	Ccy     string `xml:"Ccy"`
	GeoArea string `xml:"GeoArea"`
}

// AdditionalReference3 ...
type AdditionalReference3 struct {
	Ref     string                      `xml:"Ref"`
	RefIssr *PartyIdentification2Choice `xml:"RefIssr"`
	MsgNm   string                      `xml:"MsgNm"`
}

// AddressType2Code ...
type AddressType2Code string

// AlternateSecurityIdentification1 ...
type AlternateSecurityIdentification1 struct {
	Id         string `xml:"Id"`
	DmstIdSrc  string `xml:"DmstIdSrc"`
	PrtryIdSrc string `xml:"PrtryIdSrc"`
}

// AnyBICIdentifier ...
type AnyBICIdentifier string

// BelgianIdentifier ...
type BelgianIdentifier string

// BloombergIdentifier ...
type BloombergIdentifier string

// BreakdownByCountry1 ...
type BreakdownByCountry1 struct {
	Ctry       string              `xml:"Ctry"`
	CshInFcst  []*CashInForecast3  `xml:"CshInFcst"`
	CshOutFcst []*CashOutForecast3 `xml:"CshOutFcst"`
	NetCshFcst []*NetCashForecast2 `xml:"NetCshFcst"`
}

// BreakdownByCurrency1 ...
type BreakdownByCurrency1 struct {
	Ccy        string              `xml:"Ccy"`
	CshOutFcst []*CashOutForecast3 `xml:"CshOutFcst"`
	CshInFcst  []*CashInForecast3  `xml:"CshInFcst"`
	NetCshFcst []*NetCashForecast2 `xml:"NetCshFcst"`
}

// BreakdownByParty1 ...
type BreakdownByParty1 struct {
	Pty         *PartyIdentification2Choice `xml:"Pty"`
	AddtlParams *AdditionalParameters1      `xml:"AddtlParams"`
	CshInFcst   []*CashInForecast3          `xml:"CshInFcst"`
	CshOutFcst  []*CashOutForecast3         `xml:"CshOutFcst"`
	NetCshFcst  []*NetCashForecast2         `xml:"NetCshFcst"`
}

// BreakdownByUserDefinedParameter1 ...
type BreakdownByUserDefinedParameter1 struct {
	Pty        *PartyIdentification2Choice `xml:"Pty"`
	Ctry       string                      `xml:"Ctry"`
	Ccy        string                      `xml:"Ccy"`
	UsrDfnd    *DataFormat2Choice          `xml:"UsrDfnd"`
	CshInFcst  []*CashInForecast3          `xml:"CshInFcst"`
	CshOutFcst []*CashOutForecast3         `xml:"CshOutFcst"`
	NetCshFcst []*NetCashForecast2         `xml:"NetCshFcst"`
}

// CUSIPIdentifier ...
type CUSIPIdentifier string

// CashInForecast3 ...
type CashInForecast3 struct {
	CshSttlmDt       string                             `xml:"CshSttlmDt"`
	SubTtlAmt        *ActiveOrHistoricCurrencyAndAmount `xml:"SubTtlAmt"`
	SubTtlUnitsNb    *FinancialInstrumentQuantity1      `xml:"SubTtlUnitsNb"`
	XcptnlCshFlowInd bool                               `xml:"XcptnlCshFlowInd"`
	CshInBrkdwnDtls  []*FundCashInBreakdown2            `xml:"CshInBrkdwnDtls"`
}

// CashOutForecast3 ...
type CashOutForecast3 struct {
	CshSttlmDt       string                             `xml:"CshSttlmDt"`
	SubTtlAmt        *ActiveOrHistoricCurrencyAndAmount `xml:"SubTtlAmt"`
	SubTtlUnitsNb    *FinancialInstrumentQuantity1      `xml:"SubTtlUnitsNb"`
	XcptnlCshFlowInd bool                               `xml:"XcptnlCshFlowInd"`
	CshOutBrkdwnDtls []*FundCashOutBreakdown2           `xml:"CshOutBrkdwnDtls"`
}

// Charge16 ...
type Charge16 struct {
	Tp       string                            `xml:"Tp"`
	XtndedTp string                            `xml:"XtndedTp"`
	Amt      *ActiveCurrencyAnd13DecimalAmount `xml:"Amt"`
	Rate     float64                           `xml:"Rate"`
}

// ChargeType10Code ...
type ChargeType10Code string

// Commission9 ...
type Commission9 struct {
	Tp       string                                      `xml:"Tp"`
	XtndedTp string                                      `xml:"XtndedTp"`
	Amt      *ActiveOrHistoricCurrencyAnd13DecimalAmount `xml:"Amt"`
	Rate     float64                                     `xml:"Rate"`
}

// CommissionType6Code ...
type CommissionType6Code string

// ConsolidatedTapeAssociationIdentifier ...
type ConsolidatedTapeAssociationIdentifier string

// CountryCode ...
type CountryCode string

// DataFormat2Choice ...
type DataFormat2Choice struct {
	Strd  *GenericIdentification1 `xml:"Strd"`
	Ustrd string                  `xml:"Ustrd"`
}

// DateAndDateTimeChoice ...
type DateAndDateTimeChoice struct {
	Dt   string `xml:"Dt"`
	DtTm string `xml:"DtTm"`
}

// DecimalNumber ...
type DecimalNumber float64

// DistributionPolicy1Code ...
type DistributionPolicy1Code string

// DutchIdentifier ...
type DutchIdentifier string

// EuroclearClearstreamIdentifier ...
type EuroclearClearstreamIdentifier string

// Extended350Code ...
type Extended350Code string

// Extension1 ...
type Extension1 struct {
	PlcAndNm string `xml:"PlcAndNm"`
	Txt      string `xml:"Txt"`
}

// FinancialInstrument9 ...
type FinancialInstrument9 struct {
	Id          *SecurityIdentification3Choice `xml:"Id"`
	Nm          string                         `xml:"Nm"`
	SplmtryId   string                         `xml:"SplmtryId"`
	ReqdNAVCcy  string                         `xml:"ReqdNAVCcy"`
	ClssTp      string                         `xml:"ClssTp"`
	SctiesForm  string                         `xml:"SctiesForm"`
	DstrbtnPlcy string                         `xml:"DstrbtnPlcy"`
	DualFndInd  bool                           `xml:"DualFndInd"`
}

// FinancialInstrumentQuantity1 ...
type FinancialInstrumentQuantity1 struct {
	Unit float64 `xml:"Unit"`
}

// FlowDirectionType1Code ...
type FlowDirectionType1Code string

// FormOfSecurity1Code ...
type FormOfSecurity1Code string

// FundCashForecast4 ...
type FundCashForecast4 struct {
	Id                   string                              `xml:"Id"`
	TradDtTm             *DateAndDateTimeChoice              `xml:"TradDtTm"`
	PrvsTradDtTm         *DateAndDateTimeChoice              `xml:"PrvsTradDtTm"`
	FinInstrmDtls        *FinancialInstrument9               `xml:"FinInstrmDtls"`
	TtlNAV               *ActiveOrHistoricCurrencyAndAmount  `xml:"TtlNAV"`
	PrvsTtlNAV           *ActiveOrHistoricCurrencyAndAmount  `xml:"PrvsTtlNAV"`
	TtlUnitsNb           *FinancialInstrumentQuantity1       `xml:"TtlUnitsNb"`
	PrvsTtlUnitsNb       *FinancialInstrumentQuantity1       `xml:"PrvsTtlUnitsNb"`
	TtlNAVChngRate       float64                             `xml:"TtlNAVChngRate"`
	InvstmtCcy           []string                            `xml:"InvstmtCcy"`
	NetCshFcstDtls       []*NetCashForecast2                 `xml:"NetCshFcstDtls"`
	XcptnlNetCshFlowInd  bool                                `xml:"XcptnlNetCshFlowInd"`
	BrkdwnByCtry         []*BreakdownByCountry1              `xml:"BrkdwnByCtry"`
	BrkdwnByCcy          []*BreakdownByCurrency1             `xml:"BrkdwnByCcy"`
	BrkdwnByPty          []*BreakdownByParty1                `xml:"BrkdwnByPty"`
	BrkdwnByUsrDfndParam []*BreakdownByUserDefinedParameter1 `xml:"BrkdwnByUsrDfndParam"`
}

// FundCashInBreakdown2 ...
type FundCashInBreakdown2 struct {
	Amt                    *ActiveOrHistoricCurrencyAndAmount `xml:"Amt"`
	UnitsNb                *FinancialInstrumentQuantity1      `xml:"UnitsNb"`
	NewAmtInd              bool                               `xml:"NewAmtInd"`
	InvstmtFndTxInTp       string                             `xml:"InvstmtFndTxInTp"`
	XtndedInvstmtFndTxInTp string                             `xml:"XtndedInvstmtFndTxInTp"`
	OrgnlOrdrQtyTp         string                             `xml:"OrgnlOrdrQtyTp"`
	XtndedOrgnlOrdrQtyTp   string                             `xml:"XtndedOrgnlOrdrQtyTp"`
	ChrgDtls               []*Charge16                        `xml:"ChrgDtls"`
	ComssnDtls             []*Commission9                     `xml:"ComssnDtls"`
}

// FundCashOutBreakdown2 ...
type FundCashOutBreakdown2 struct {
	Amt                     *ActiveOrHistoricCurrencyAndAmount `xml:"Amt"`
	UnitsNb                 *FinancialInstrumentQuantity1      `xml:"UnitsNb"`
	NewAmtInd               bool                               `xml:"NewAmtInd"`
	InvstmtFndTxOutTp       string                             `xml:"InvstmtFndTxOutTp"`
	XtndedInvstmtFndTxOutTp string                             `xml:"XtndedInvstmtFndTxOutTp"`
	OrgnlOrdrQtyTp          string                             `xml:"OrgnlOrdrQtyTp"`
	XtndedOrgnlOrdrQtyTp    string                             `xml:"XtndedOrgnlOrdrQtyTp"`
	ChrgDtls                []*Charge16                        `xml:"ChrgDtls"`
	ComssnDtls              []*Commission9                     `xml:"ComssnDtls"`
}

// FundDetailedConfirmedCashForecastReportV03 ...
type FundDetailedConfirmedCashForecastReportV03 struct {
	MsgId            *MessageIdentification1 `xml:"MsgId"`
	PoolRef          *AdditionalReference3   `xml:"PoolRef"`
	PrvsRef          []*AdditionalReference3 `xml:"PrvsRef"`
	RltdRef          []*AdditionalReference3 `xml:"RltdRef"`
	MsgPgntn         *Pagination             `xml:"MsgPgntn"`
	FndCshFcstDtls   []*FundCashForecast4    `xml:"FndCshFcstDtls"`
	CnsltdNetCshFcst *NetCashForecast3       `xml:"CnsltdNetCshFcst"`
	Xtnsn            []*Extension1           `xml:"Xtnsn"`
}

// GenericIdentification1 ...
type GenericIdentification1 struct {
	Id      string `xml:"Id"`
	SchmeNm string `xml:"SchmeNm"`
	Issr    string `xml:"Issr"`
}

// ISINIdentifier ...
type ISINIdentifier string

// ISODate ...
type ISODate string

// ISODateTime ...
type ISODateTime string

// InvestmentFundTransactionInType1Code ...
type InvestmentFundTransactionInType1Code string

// InvestmentFundTransactionOutType1Code ...
type InvestmentFundTransactionOutType1Code string

// Max140Text ...
type Max140Text string

// Max16Text ...
type Max16Text string

// Max350Text ...
type Max350Text string

// Max35Text ...
type Max35Text string

// Max5NumericText ...
type Max5NumericText string

// Max70Text ...
type Max70Text string

// MessageIdentification1 ...
type MessageIdentification1 struct {
	Id      string `xml:"Id"`
	CreDtTm string `xml:"CreDtTm"`
}

// NameAndAddress5 ...
type NameAndAddress5 struct {
	Nm  string          `xml:"Nm"`
	Adr *PostalAddress1 `xml:"Adr"`
}

// NetCashForecast2 ...
type NetCashForecast2 struct {
	CshSttlmDt string                             `xml:"CshSttlmDt"`
	NetAmt     *ActiveOrHistoricCurrencyAndAmount `xml:"NetAmt"`
	NetUnitsNb *FinancialInstrumentQuantity1      `xml:"NetUnitsNb"`
	FlowDrctn  string                             `xml:"FlowDrctn"`
}

// NetCashForecast3 ...
type NetCashForecast3 struct {
	NetAmt     *ActiveOrHistoricCurrencyAndAmount `xml:"NetAmt"`
	NetUnitsNb *FinancialInstrumentQuantity1      `xml:"NetUnitsNb"`
	FlowDrctn  string                             `xml:"FlowDrctn"`
}

// OrderQuantityType2Code ...
type OrderQuantityType2Code string

// Pagination ...
type Pagination struct {
	PgNb      string `xml:"PgNb"`
	LastPgInd bool   `xml:"LastPgInd"`
}

// PartyIdentification2Choice ...
type PartyIdentification2Choice struct {
	BICOrBEI string                  `xml:"BICOrBEI"`
	PrtryId  *GenericIdentification1 `xml:"PrtryId"`
	NmAndAdr *NameAndAddress5        `xml:"NmAndAdr"`
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

// QUICKIdentifier ...
type QUICKIdentifier string

// RICIdentifier ...
type RICIdentifier string

// SEDOLIdentifier ...
type SEDOLIdentifier string

// SecurityIdentification3Choice ...
type SecurityIdentification3Choice struct {
	ISIN        string                            `xml:"ISIN"`
	SEDOL       string                            `xml:"SEDOL"`
	CUSIP       string                            `xml:"CUSIP"`
	RIC         string                            `xml:"RIC"`
	TckrSymb    string                            `xml:"TckrSymb"`
	Blmbrg      string                            `xml:"Blmbrg"`
	CTA         string                            `xml:"CTA"`
	QUICK       string                            `xml:"QUICK"`
	Wrtppr      string                            `xml:"Wrtppr"`
	Dtch        string                            `xml:"Dtch"`
	Vlrn        string                            `xml:"Vlrn"`
	SCVM        string                            `xml:"SCVM"`
	Belgn       string                            `xml:"Belgn"`
	Cmon        string                            `xml:"Cmon"`
	OthrPrtryId *AlternateSecurityIdentification1 `xml:"OthrPrtryId"`
}

// SicovamIdentifier ...
type SicovamIdentifier string

// TickerIdentifier ...
type TickerIdentifier string

// ValorenIdentifier ...
type ValorenIdentifier string

// WertpapierIdentifier ...
type WertpapierIdentifier string

// YesNoIndicator ...
type YesNoIndicator bool
