package schema

import (
	"time"
)

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

// AddressType2Code ...
type AddressType2Code string

// AnyBICIdentifier ...
type AnyBICIdentifier string

// ClearingSystemIdentification2Choice ...
type ClearingSystemIdentification2Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// CountryCode ...
type CountryCode string

// ExternalClearingSystemIdentification1Code ...
type ExternalClearingSystemIdentification1Code string

// ISODate ...
type ISODate string

// ISODateTime ...
type ISODateTime string

// ISOTime ...
type ISOTime time.Time

// LEIIdentifier ...
type LEIIdentifier string

// Max105Text ...
type Max105Text string

// Max10NumericText ...
type Max10NumericText string

// Max16Text ...
type Max16Text string

// Max34Text ...
type Max34Text string

// Max350Text ...
type Max350Text string

// Max35Text ...
type Max35Text string

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

// NetObligation1 ...
type NetObligation1 struct {
	OblgtnId          string                        `xml:"OblgtnId"`
	Amt               *ActiveCurrencyAndAmount      `xml:"Amt"`
	PtcptNetgId       *NettingIdentification1Choice `xml:"PtcptNetgId"`
	OblgtnDrctn       string                        `xml:"OblgtnDrctn"`
	CtrPtyNetgId      *NettingIdentification1Choice `xml:"CtrPtyNetgId"`
	NetSvcCtrPtyId    *PartyIdentification73Choice  `xml:"NetSvcCtrPtyId"`
	CtrPtySttlmInstrs *SettlementParties29          `xml:"CtrPtySttlmInstrs"`
	TxsNb             string                        `xml:"TxsNb"`
}

// NetReportData1 ...
type NetReportData1 struct {
	MsgId        string                       `xml:"MsgId"`
	CreDtTm      string                       `xml:"CreDtTm"`
	NetgCutOffTm time.Time                    `xml:"NetgCutOffTm"`
	RptDt        string                       `xml:"RptDt"`
	ValDt        string                       `xml:"ValDt"`
	RptTp        string                       `xml:"RptTp"`
	NetRptSvcr   *PartyIdentification73Choice `xml:"NetRptSvcr"`
	NetSvcTp     string                       `xml:"NetSvcTp"`
	MsgPgntn     *Pagination                  `xml:"MsgPgntn"`
}

// NetReportV01 ...
type NetReportV01 struct {
	NetRptData     *NetReportData1              `xml:"NetRptData"`
	NetSvcPtcptId  *PartyIdentification73Choice `xml:"NetSvcPtcptId"`
	NetSvcCtrPtyId *PartyIdentification73Choice `xml:"NetSvcCtrPtyId"`
	NetOblgtn      []*NetObligation1            `xml:"NetOblgtn"`
	SplmtryData    []*SupplementaryData1        `xml:"SplmtryData"`
}

// NettingIdentification1Choice ...
type NettingIdentification1Choice struct {
	TradPty   *PartyIdentification73Choice `xml:"TradPty"`
	NetgGrpId string                       `xml:"NetgGrpId"`
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

// PaymentReceipt1Code ...
type PaymentReceipt1Code string

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

// SettlementParties29 ...
type SettlementParties29 struct {
	DlvryAgt    *PartyIdentification73Choice `xml:"DlvryAgt"`
	Intrmy      *PartyIdentification73Choice `xml:"Intrmy"`
	RcvgAgt     *PartyIdentification73Choice `xml:"RcvgAgt"`
	BnfcryInstn *PartyIdentification73Choice `xml:"BnfcryInstn"`
}

// SupplementaryData1 ...
type SupplementaryData1 struct {
	PlcAndNm string                      `xml:"PlcAndNm"`
	Envlp    *SupplementaryDataEnvelope1 `xml:"Envlp"`
}

// SupplementaryDataEnvelope1 ...
type SupplementaryDataEnvelope1 struct {
}

// YesNoIndicator ...
type YesNoIndicator bool
