package schema

// Document ...
type Document *Document

// AccountIdentification1 ...
type AccountIdentification1 struct {
	Prtry *SimpleIdentificationInformation `xml:"Prtry"`
}

// ActiveCurrencyAnd13DecimalAmountSimpleType ...
type ActiveCurrencyAnd13DecimalAmountSimpleType float64

// ActiveCurrencyAnd13DecimalAmount ...
type ActiveCurrencyAnd13DecimalAmount struct {
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

// AmountOrRate3Choice ...
type AmountOrRate3Choice struct {
	Amt  *ActiveCurrencyAnd13DecimalAmount `xml:"Amt"`
	Rate float64                           `xml:"Rate"`
}

// AnyBICIdentifier ...
type AnyBICIdentifier string

// BaseOneRate ...
type BaseOneRate float64

// BelgianIdentifier ...
type BelgianIdentifier string

// BloombergIdentifier ...
type BloombergIdentifier string

// BreakdownByCountry2 ...
type BreakdownByCountry2 struct {
	Ctry       string              `xml:"Ctry"`
	CshInFcst  []*CashInForecast5  `xml:"CshInFcst"`
	CshOutFcst []*CashOutForecast5 `xml:"CshOutFcst"`
	NetCshFcst []*NetCashForecast4 `xml:"NetCshFcst"`
}

// BreakdownByCurrency2 ...
type BreakdownByCurrency2 struct {
	Ccy        string              `xml:"Ccy"`
	CshOutFcst []*CashOutForecast5 `xml:"CshOutFcst"`
	CshInFcst  []*CashInForecast5  `xml:"CshInFcst"`
	NetCshFcst []*NetCashForecast4 `xml:"NetCshFcst"`
}

// BreakdownByParty3 ...
type BreakdownByParty3 struct {
	Pty         *InvestmentAccount42   `xml:"Pty"`
	AddtlParams *AdditionalParameters1 `xml:"AddtlParams"`
	CshInFcst   []*CashInForecast5     `xml:"CshInFcst"`
	CshOutFcst  []*CashOutForecast5    `xml:"CshOutFcst"`
	NetCshFcst  []*NetCashForecast4    `xml:"NetCshFcst"`
}

// BreakdownByUserDefinedParameter3 ...
type BreakdownByUserDefinedParameter3 struct {
	Pty        *InvestmentAccount42 `xml:"Pty"`
	Ctry       string               `xml:"Ctry"`
	Ccy        string               `xml:"Ccy"`
	UsrDfnd    *DataFormat2Choice   `xml:"UsrDfnd"`
	CshInFcst  []*CashInForecast5   `xml:"CshInFcst"`
	CshOutFcst []*CashOutForecast5  `xml:"CshOutFcst"`
	NetCshFcst []*NetCashForecast4  `xml:"NetCshFcst"`
}

// CUSIPIdentifier ...
type CUSIPIdentifier string

// CashInForecast5 ...
type CashInForecast5 struct {
	CshSttlmDt       string                             `xml:"CshSttlmDt"`
	SubTtlAmt        *ActiveOrHistoricCurrencyAndAmount `xml:"SubTtlAmt"`
	SubTtlUnitsNb    *FinancialInstrumentQuantity1      `xml:"SubTtlUnitsNb"`
	XcptnlCshFlowInd bool                               `xml:"XcptnlCshFlowInd"`
	CshInBrkdwnDtls  []*FundCashInBreakdown3            `xml:"CshInBrkdwnDtls"`
	AddtlBal         *FundBalance1                      `xml:"AddtlBal"`
}

// CashOutForecast5 ...
type CashOutForecast5 struct {
	CshSttlmDt       string                             `xml:"CshSttlmDt"`
	SubTtlAmt        *ActiveOrHistoricCurrencyAndAmount `xml:"SubTtlAmt"`
	SubTtlUnitsNb    *FinancialInstrumentQuantity1      `xml:"SubTtlUnitsNb"`
	XcptnlCshFlowInd bool                               `xml:"XcptnlCshFlowInd"`
	CshOutBrkdwnDtls []*FundCashOutBreakdown3           `xml:"CshOutBrkdwnDtls"`
	AddtlBal         *FundBalance1                      `xml:"AddtlBal"`
}

// Charge26 ...
type Charge26 struct {
	Tp       *ChargeType4Choice   `xml:"Tp"`
	ChrgApld *AmountOrRate3Choice `xml:"ChrgApld"`
}

// ChargeType12Code ...
type ChargeType12Code string

// ChargeType4Choice ...
type ChargeType4Choice struct {
	Cd    string                   `xml:"Cd"`
	Prtry *GenericIdentification47 `xml:"Prtry"`
}

// Commission21 ...
type Commission21 struct {
	ComssnTp   *CommissionType5Choice `xml:"ComssnTp"`
	ComssnApld *AmountOrRate3Choice   `xml:"ComssnApld"`
}

// CommissionType5Choice ...
type CommissionType5Choice struct {
	Cd    string                   `xml:"Cd"`
	Prtry *GenericIdentification47 `xml:"Prtry"`
}

// CommissionType6Code ...
type CommissionType6Code string

// ConsolidatedTapeAssociationIdentifier ...
type ConsolidatedTapeAssociationIdentifier string

// CountryCode ...
type CountryCode string

// CurrencyDesignation1 ...
type CurrencyDesignation1 struct {
	CcyDsgnt string `xml:"CcyDsgnt"`
	Lctn     string `xml:"Lctn"`
	AddtlInf string `xml:"AddtlInf"`
}

// CurrencyDesignation1Code ...
type CurrencyDesignation1Code string

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

// EstimatedFundCashForecast5 ...
type EstimatedFundCashForecast5 struct {
	Id                        string                               `xml:"Id"`
	TradDtTm                  *DateAndDateTimeChoice               `xml:"TradDtTm"`
	PrvsTradDtTm              *DateAndDateTimeChoice               `xml:"PrvsTradDtTm"`
	FinInstrmDtls             *FinancialInstrument9                `xml:"FinInstrmDtls"`
	EstmtdTtlNAV              []*ActiveOrHistoricCurrencyAndAmount `xml:"EstmtdTtlNAV"`
	PrvsTtlNAV                []*ActiveOrHistoricCurrencyAndAmount `xml:"PrvsTtlNAV"`
	EstmtdTtlUnitsNb          *FinancialInstrumentQuantity1        `xml:"EstmtdTtlUnitsNb"`
	PrvsTtlUnitsNb            *FinancialInstrumentQuantity1        `xml:"PrvsTtlUnitsNb"`
	EstmtdTtlNAVChngRate      float64                              `xml:"EstmtdTtlNAVChngRate"`
	InvstmtCcy                []string                             `xml:"InvstmtCcy"`
	CcySts                    *CurrencyDesignation1                `xml:"CcySts"`
	XcptnlNetCshFlowInd       bool                                 `xml:"XcptnlNetCshFlowInd"`
	Pric                      *UnitPrice19                         `xml:"Pric"`
	FXRate                    *ForeignExchangeTerms19              `xml:"FXRate"`
	EstmtdPctgOfShrClssTtlNAV float64                              `xml:"EstmtdPctgOfShrClssTtlNAV"`
	BrkdwnByPty               []*BreakdownByParty3                 `xml:"BrkdwnByPty"`
	BrkdwnByCtry              []*BreakdownByCountry2               `xml:"BrkdwnByCtry"`
	BrkdwnByCcy               []*BreakdownByCurrency2              `xml:"BrkdwnByCcy"`
	BrkdwnByUsrDfndParam      []*BreakdownByUserDefinedParameter3  `xml:"BrkdwnByUsrDfndParam"`
	EstmtdNetCshFcstDtls      []*NetCashForecast4                  `xml:"EstmtdNetCshFcstDtls"`
}

// EuroclearClearstreamIdentifier ...
type EuroclearClearstreamIdentifier string

// Exact4AlphaNumericText ...
type Exact4AlphaNumericText string

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

// ForeignExchangeTerms19 ...
type ForeignExchangeTerms19 struct {
	UnitCcy  string  `xml:"UnitCcy"`
	QtdCcy   string  `xml:"QtdCcy"`
	XchgRate float64 `xml:"XchgRate"`
}

// FormOfSecurity1Code ...
type FormOfSecurity1Code string

// Fund3 ...
type Fund3 struct {
	Nm                    string                             `xml:"Nm"`
	LglNttyIdr            string                             `xml:"LglNttyIdr"`
	Id                    *OtherIdentification4              `xml:"Id"`
	Ccy                   string                             `xml:"Ccy"`
	EstmtdTtlNAV          *ActiveOrHistoricCurrencyAndAmount `xml:"EstmtdTtlNAV"`
	PrvsTtlNAV            *ActiveOrHistoricCurrencyAndAmount `xml:"PrvsTtlNAV"`
	EstmtdTtlUnitsNb      *FinancialInstrumentQuantity1      `xml:"EstmtdTtlUnitsNb"`
	PrvsTtlUnitsNb        *FinancialInstrumentQuantity1      `xml:"PrvsTtlUnitsNb"`
	EstmtdPctgOfFndTtlNAV float64                            `xml:"EstmtdPctgOfFndTtlNAV"`
}

// FundBalance1 ...
type FundBalance1 struct {
	TtlUnitsFrUnitOrdrs *FinancialInstrumentQuantity1      `xml:"TtlUnitsFrUnitOrdrs"`
	TtlUnitsFrCshOrdrs  *FinancialInstrumentQuantity1      `xml:"TtlUnitsFrCshOrdrs"`
	TtlCshFrUnitOrdrs   *ActiveOrHistoricCurrencyAndAmount `xml:"TtlCshFrUnitOrdrs"`
	TtlCshFrCshOrdrs    *ActiveOrHistoricCurrencyAndAmount `xml:"TtlCshFrCshOrdrs"`
}

// FundCashInBreakdown3 ...
type FundCashInBreakdown3 struct {
	Amt              *ActiveOrHistoricCurrencyAndAmount      `xml:"Amt"`
	UnitsNb          *FinancialInstrumentQuantity1           `xml:"UnitsNb"`
	NewAmtInd        bool                                    `xml:"NewAmtInd"`
	InvstmtFndTxInTp *InvestmentFundTransactionInType1Choice `xml:"InvstmtFndTxInTp"`
	OrgnlOrdrQtyTp   *QuantityType1Choice                    `xml:"OrgnlOrdrQtyTp"`
	ChrgDtls         []*Charge26                             `xml:"ChrgDtls"`
	ComssnDtls       []*Commission21                         `xml:"ComssnDtls"`
	SttlmCcy         string                                  `xml:"SttlmCcy"`
}

// FundCashOutBreakdown3 ...
type FundCashOutBreakdown3 struct {
	Amt               *ActiveOrHistoricCurrencyAndAmount       `xml:"Amt"`
	UnitsNb           *FinancialInstrumentQuantity1            `xml:"UnitsNb"`
	NewAmtInd         bool                                     `xml:"NewAmtInd"`
	InvstmtFndTxOutTp *InvestmentFundTransactionOutType1Choice `xml:"InvstmtFndTxOutTp"`
	OrgnlOrdrQtyTp    *QuantityType1Choice                     `xml:"OrgnlOrdrQtyTp"`
	ChrgDtls          []*Charge26                              `xml:"ChrgDtls"`
	ComssnDtls        []*Commission21                          `xml:"ComssnDtls"`
	SttlmCcy          string                                   `xml:"SttlmCcy"`
}

// FundDetailedEstimatedCashForecastReportV04 ...
type FundDetailedEstimatedCashForecastReportV04 struct {
	MsgId                *MessageIdentification1       `xml:"MsgId"`
	PoolRef              *AdditionalReference3         `xml:"PoolRef"`
	PrvsRef              []*AdditionalReference3       `xml:"PrvsRef"`
	RltdRef              []*AdditionalReference3       `xml:"RltdRef"`
	MsgPgntn             *Pagination                   `xml:"MsgPgntn"`
	FndOrSubFndDtls      *Fund3                        `xml:"FndOrSubFndDtls"`
	EstmtdFndCshFcstDtls []*EstimatedFundCashForecast5 `xml:"EstmtdFndCshFcstDtls"`
	CnsltdNetCshFcst     *NetCashForecast3             `xml:"CnsltdNetCshFcst"`
	Xtnsn                []*Extension1                 `xml:"Xtnsn"`
}

// GenericIdentification1 ...
type GenericIdentification1 struct {
	Id      string `xml:"Id"`
	SchmeNm string `xml:"SchmeNm"`
	Issr    string `xml:"Issr"`
}

// GenericIdentification47 ...
type GenericIdentification47 struct {
	Id      string `xml:"Id"`
	Issr    string `xml:"Issr"`
	SchmeNm string `xml:"SchmeNm"`
}

// ISINIdentifier ...
type ISINIdentifier string

// ISODate ...
type ISODate string

// ISODateTime ...
type ISODateTime string

// IdentificationSource5Choice ...
type IdentificationSource5Choice struct {
	DmstIdSrc  string `xml:"DmstIdSrc"`
	PrtryIdSrc string `xml:"PrtryIdSrc"`
}

// InvestmentAccount42 ...
type InvestmentAccount42 struct {
	AcctId   *AccountIdentification1     `xml:"AcctId"`
	OwnrId   *PartyIdentification2Choice `xml:"OwnrId"`
	AcctSvcr *PartyIdentification2Choice `xml:"AcctSvcr"`
}

// InvestmentFundTransactionInType1Choice ...
type InvestmentFundTransactionInType1Choice struct {
	Cd    string                   `xml:"Cd"`
	Prtry *GenericIdentification47 `xml:"Prtry"`
}

// InvestmentFundTransactionInType1Code ...
type InvestmentFundTransactionInType1Code string

// InvestmentFundTransactionOutType1Choice ...
type InvestmentFundTransactionOutType1Choice struct {
	Cd    string                   `xml:"Cd"`
	Prtry *GenericIdentification47 `xml:"Prtry"`
}

// InvestmentFundTransactionOutType1Code ...
type InvestmentFundTransactionOutType1Code string

// LEIIdentifier ...
type LEIIdentifier string

// Max140Text ...
type Max140Text string

// Max16Text ...
type Max16Text string

// Max350Text ...
type Max350Text string

// Max35Text ...
type Max35Text string

// Max4AlphaNumericText ...
type Max4AlphaNumericText string

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

// NetCashForecast3 ...
type NetCashForecast3 struct {
	NetAmt     *ActiveOrHistoricCurrencyAndAmount `xml:"NetAmt"`
	NetUnitsNb *FinancialInstrumentQuantity1      `xml:"NetUnitsNb"`
	FlowDrctn  string                             `xml:"FlowDrctn"`
}

// NetCashForecast4 ...
type NetCashForecast4 struct {
	CshSttlmDt string                             `xml:"CshSttlmDt"`
	NetAmt     *ActiveOrHistoricCurrencyAndAmount `xml:"NetAmt"`
	NetUnitsNb *FinancialInstrumentQuantity1      `xml:"NetUnitsNb"`
	FlowDrctn  string                             `xml:"FlowDrctn"`
	AddtlBal   *FundBalance1                      `xml:"AddtlBal"`
}

// OrderQuantityType2Code ...
type OrderQuantityType2Code string

// OtherIdentification4 ...
type OtherIdentification4 struct {
	Id string                       `xml:"Id"`
	Tp *IdentificationSource5Choice `xml:"Tp"`
}

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

// PriceValue1 ...
type PriceValue1 struct {
	Amt *ActiveCurrencyAnd13DecimalAmount `xml:"Amt"`
}

// QUICKIdentifier ...
type QUICKIdentifier string

// QuantityType1Choice ...
type QuantityType1Choice struct {
	Cd    string                   `xml:"Cd"`
	Prtry *GenericIdentification47 `xml:"Prtry"`
}

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

// SimpleIdentificationInformation ...
type SimpleIdentificationInformation struct {
	Id string `xml:"Id"`
}

// TickerIdentifier ...
type TickerIdentifier string

// TypeOfPrice10Code ...
type TypeOfPrice10Code string

// UnitPrice19 ...
type UnitPrice19 struct {
	PricTp *UnitPriceType2Choice `xml:"PricTp"`
	Val    *PriceValue1          `xml:"Val"`
}

// UnitPriceType2Choice ...
type UnitPriceType2Choice struct {
	Cd    string                   `xml:"Cd"`
	Prtry *GenericIdentification47 `xml:"Prtry"`
}

// ValorenIdentifier ...
type ValorenIdentifier string

// WertpapierIdentifier ...
type WertpapierIdentifier string

// YesNoIndicator ...
type YesNoIndicator bool
