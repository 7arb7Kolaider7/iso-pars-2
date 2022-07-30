package schema

// Document ...
type Document *Document

// ActiveOrHistoricCurrencyCode ...
type ActiveOrHistoricCurrencyCode string

// BaseOneRate ...
type BaseOneRate float64

// CurrencyExchange7 ...
type CurrencyExchange7 struct {
	XchgRate float64 `xml:"XchgRate"`
	QtdCcy   string  `xml:"QtdCcy"`
	QtnDt    string  `xml:"QtnDt"`
}

// CurrencyExchangeReport3 ...
type CurrencyExchangeReport3 struct {
	CcyRef       *CurrencySourceTarget1            `xml:"CcyRef"`
	CcyXchgOrErr *ExchangeRateReportOrError2Choice `xml:"CcyXchgOrErr"`
}

// CurrencySourceTarget1 ...
type CurrencySourceTarget1 struct {
	SrcCcy  string `xml:"SrcCcy"`
	TrgtCcy string `xml:"TrgtCcy"`
}

// ErrorHandling1Choice ...
type ErrorHandling1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// ErrorHandling1Code ...
type ErrorHandling1Code string

// ErrorHandling3 ...
type ErrorHandling3 struct {
	Err  *ErrorHandling1Choice `xml:"Err"`
	Desc string                `xml:"Desc"`
}

// ExchangeRateReportOrError1Choice ...
type ExchangeRateReportOrError1Choice struct {
	CcyXchgRpt []*CurrencyExchangeReport3 `xml:"CcyXchgRpt"`
	OprlErr    []*ErrorHandling3          `xml:"OprlErr"`
}

// ExchangeRateReportOrError2Choice ...
type ExchangeRateReportOrError2Choice struct {
	BizErr  []*ErrorHandling3  `xml:"BizErr"`
	CcyXchg *CurrencyExchange7 `xml:"CcyXchg"`
}

// ExternalEnquiryRequestType1Code ...
type ExternalEnquiryRequestType1Code string

// ExternalPaymentControlRequestType1Code ...
type ExternalPaymentControlRequestType1Code string

// GenericIdentification1 ...
type GenericIdentification1 struct {
	Id      string `xml:"Id"`
	SchmeNm string `xml:"SchmeNm"`
	Issr    string `xml:"Issr"`
}

// ISODateTime ...
type ISODateTime string

// Max140Text ...
type Max140Text string

// Max350Text ...
type Max350Text string

// Max35Text ...
type Max35Text string

// Max4AlphaNumericText ...
type Max4AlphaNumericText string

// MessageHeader7 ...
type MessageHeader7 struct {
	MsgId       string                  `xml:"MsgId"`
	CreDtTm     string                  `xml:"CreDtTm"`
	ReqTp       *RequestType4Choice     `xml:"ReqTp"`
	OrgnlBizQry *OriginalBusinessQuery1 `xml:"OrgnlBizQry"`
	QryNm       string                  `xml:"QryNm"`
}

// OriginalBusinessQuery1 ...
type OriginalBusinessQuery1 struct {
	MsgId   string `xml:"MsgId"`
	MsgNmId string `xml:"MsgNmId"`
	CreDtTm string `xml:"CreDtTm"`
}

// RequestType4Choice ...
type RequestType4Choice struct {
	PmtCtrl string                  `xml:"PmtCtrl"`
	Enqry   string                  `xml:"Enqry"`
	Prtry   *GenericIdentification1 `xml:"Prtry"`
}

// ReturnCurrencyExchangeRateV04 ...
type ReturnCurrencyExchangeRateV04 struct {
	MsgHdr      *MessageHeader7                   `xml:"MsgHdr"`
	RptOrErr    *ExchangeRateReportOrError1Choice `xml:"RptOrErr"`
	SplmtryData []*SupplementaryData1             `xml:"SplmtryData"`
}

// SupplementaryData1 ...
type SupplementaryData1 struct {
	PlcAndNm string                      `xml:"PlcAndNm"`
	Envlp    *SupplementaryDataEnvelope1 `xml:"Envlp"`
}

// SupplementaryDataEnvelope1 ...
type SupplementaryDataEnvelope1 struct {
}
