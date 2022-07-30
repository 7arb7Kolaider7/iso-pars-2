package schema

// Document ...
type Document *Document

// ActiveOrHistoricCurrencyCode ...
type ActiveOrHistoricCurrencyCode string

// CurrencyCriteriaDefinition1Choice ...
type CurrencyCriteriaDefinition1Choice struct {
	QryNm   string                     `xml:"QryNm"`
	NewCrit *CurrencyExchangeCriteria2 `xml:"NewCrit"`
}

// CurrencyExchangeCriteria2 ...
type CurrencyExchangeCriteria2 struct {
	NewQryNm string                             `xml:"NewQryNm"`
	SchCrit  []*CurrencyExchangeSearchCriteria1 `xml:"SchCrit"`
}

// CurrencyExchangeSearchCriteria1 ...
type CurrencyExchangeSearchCriteria1 struct {
	SrcCcy  string `xml:"SrcCcy"`
	TrgtCcy string `xml:"TrgtCcy"`
}

// CurrencyQueryDefinition3 ...
type CurrencyQueryDefinition3 struct {
	QryTp   string                             `xml:"QryTp"`
	CcyCrit *CurrencyCriteriaDefinition1Choice `xml:"CcyCrit"`
}

// GetCurrencyExchangeRateV04 ...
type GetCurrencyExchangeRateV04 struct {
	MsgHdr      *MessageHeader1           `xml:"MsgHdr"`
	CcyQryDef   *CurrencyQueryDefinition3 `xml:"CcyQryDef"`
	SplmtryData []*SupplementaryData1     `xml:"SplmtryData"`
}

// ISODateTime ...
type ISODateTime string

// Max350Text ...
type Max350Text string

// Max35Text ...
type Max35Text string

// MessageHeader1 ...
type MessageHeader1 struct {
	MsgId   string `xml:"MsgId"`
	CreDtTm string `xml:"CreDtTm"`
}

// QueryType2Code ...
type QueryType2Code string

// SupplementaryData1 ...
type SupplementaryData1 struct {
	PlcAndNm string                      `xml:"PlcAndNm"`
	Envlp    *SupplementaryDataEnvelope1 `xml:"Envlp"`
}

// SupplementaryDataEnvelope1 ...
type SupplementaryDataEnvelope1 struct {
}
