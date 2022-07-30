package schema

// Document ...
type Document *Document

// AcknowledgementDetails1Choice ...
type AcknowledgementDetails1Choice struct {
	PayInSchdlRef string `xml:"PayInSchdlRef"`
	PayInCallRef  string `xml:"PayInCallRef"`
}

// Exact4AlphaNumericText ...
type Exact4AlphaNumericText string

// Max350Text ...
type Max350Text string

// Max35Text ...
type Max35Text string

// PayInEventAcknowledgementV02 ...
type PayInEventAcknowledgementV02 struct {
	MsgId       string                         `xml:"MsgId"`
	SttlmSsnIdr string                         `xml:"SttlmSsnIdr"`
	AckDtls     *AcknowledgementDetails1Choice `xml:"AckDtls"`
	SplmtryData []*SupplementaryData1          `xml:"SplmtryData"`
}

// SupplementaryData1 ...
type SupplementaryData1 struct {
	PlcAndNm string                      `xml:"PlcAndNm"`
	Envlp    *SupplementaryDataEnvelope1 `xml:"Envlp"`
}

// SupplementaryDataEnvelope1 ...
type SupplementaryDataEnvelope1 struct {
}
