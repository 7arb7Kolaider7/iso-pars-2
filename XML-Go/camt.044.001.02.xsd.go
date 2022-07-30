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

// CUSIPIdentifier ...
type CUSIPIdentifier string

// CashInForecast4 ...
type CashInForecast4 struct {
	CshSttlmDt       string                             `xml:"CshSttlmDt"`
	SubTtlAmt        *ActiveOrHistoricCurrencyAndAmount `xml:"SubTtlAmt"`
	SubTtlUnitsNb    *FinancialInstrumentQuantity1      `xml:"SubTtlUnitsNb"`
	XcptnlCshFlowInd bool                               `xml:"XcptnlCshFlowInd"`
}

// CashOutForecast4 ...
type CashOutForecast4 struct {
	CshSttlmDt       string                             `xml:"CshSttlmDt"`
	SubTtlAmt        *ActiveOrHistoricCurrencyAndAmount `xml:"SubTtlAmt"`
	SubTtlUnitsNb    *FinancialInstrumentQuantity1      `xml:"SubTtlUnitsNb"`
	XcptnlCshFlowInd bool                               `xml:"XcptnlCshFlowInd"`
}

// ConsolidatedTapeAssociationIdentifier ...
type ConsolidatedTapeAssociationIdentifier string

// CountryCode ...
type CountryCode string

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

// FundCashForecast3 ...
type FundCashForecast3 struct {
	Id                  string                             `xml:"Id"`
	TradDtTm            *DateAndDateTimeChoice             `xml:"TradDtTm"`
	PrvsTradDtTm        *DateAndDateTimeChoice             `xml:"PrvsTradDtTm"`
	FinInstrmDtls       *FinancialInstrument9              `xml:"FinInstrmDtls"`
	TtlNAV              *ActiveOrHistoricCurrencyAndAmount `xml:"TtlNAV"`
	PrvsTtlNAV          *ActiveOrHistoricCurrencyAndAmount `xml:"PrvsTtlNAV"`
	TtlUnitsNb          *FinancialInstrumentQuantity1      `xml:"TtlUnitsNb"`
	PrvsTtlUnitsNb      *FinancialInstrumentQuantity1      `xml:"PrvsTtlUnitsNb"`
	TtlNAVChngRate      float64                            `xml:"TtlNAVChngRate"`
	InvstmtCcy          []string                           `xml:"InvstmtCcy"`
	XcptnlNetCshFlowInd bool                               `xml:"XcptnlNetCshFlowInd"`
	CshInFcstDtls       []*CashInForecast4                 `xml:"CshInFcstDtls"`
	CshOutFcstDtls      []*CashOutForecast4                `xml:"CshOutFcstDtls"`
	NetCshFcstDtls      []*NetCashForecast2                `xml:"NetCshFcstDtls"`
}

// FundConfirmedCashForecastReport2 ...
type FundConfirmedCashForecastReport2 struct {
	FndCshFcstDtls   []*FundCashForecast3 `xml:"FndCshFcstDtls"`
	CnsltdNetCshFcst *NetCashForecast3    `xml:"CnsltdNetCshFcst"`
	Xtnsn            []*Extension1        `xml:"Xtnsn"`
}

// FundConfirmedCashForecastReportCancellationV02 ...
type FundConfirmedCashForecastReportCancellationV02 struct {
	MsgId              *MessageIdentification1           `xml:"MsgId"`
	PoolRef            *AdditionalReference3             `xml:"PoolRef"`
	PrvsRef            *AdditionalReference3             `xml:"PrvsRef"`
	RltdRef            []*AdditionalReference3           `xml:"RltdRef"`
	MsgPgntn           *Pagination                       `xml:"MsgPgntn"`
	CshFcstRptToBeCanc *FundConfirmedCashForecastReport2 `xml:"CshFcstRptToBeCanc"`
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
