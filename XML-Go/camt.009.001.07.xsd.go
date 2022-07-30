package schema

// Document ...
type Document *Document

// AccountIdentification4Choice ...
type AccountIdentification4Choice struct {
	IBAN string                         `xml:"IBAN"`
	Othr *GenericAccountIdentification1 `xml:"Othr"`
}

// AccountSchemeName1Choice ...
type AccountSchemeName1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// ActiveAmountRange3Choice ...
type ActiveAmountRange3Choice struct {
	ImpldCcyAndAmtRg *ImpliedCurrencyAndAmountRange1 `xml:"ImpldCcyAndAmtRg"`
	CcyAndAmtRg      *ActiveCurrencyAndAmountRange3  `xml:"CcyAndAmtRg"`
}

// ActiveCurrencyAndAmountRange3 ...
type ActiveCurrencyAndAmountRange3 struct {
	Amt       *ImpliedCurrencyAmountRange1Choice `xml:"Amt"`
	CdtDbtInd string                             `xml:"CdtDbtInd"`
	Ccy       string                             `xml:"Ccy"`
}

// ActiveCurrencyCode ...
type ActiveCurrencyCode string

// AddressType2Code ...
type AddressType2Code string

// AddressType3Choice ...
type AddressType3Choice struct {
	Cd    string                   `xml:"Cd"`
	Prtry *GenericIdentification30 `xml:"Prtry"`
}

// AmountRangeBoundary1 ...
type AmountRangeBoundary1 struct {
	BdryAmt float64 `xml:"BdryAmt"`
	Incl    bool    `xml:"Incl"`
}

// BICFIDec2014Identifier ...
type BICFIDec2014Identifier string

// BranchAndFinancialInstitutionIdentification6 ...
type BranchAndFinancialInstitutionIdentification6 struct {
	FinInstnId *FinancialInstitutionIdentification18 `xml:"FinInstnId"`
	BrnchId    *BranchData3                          `xml:"BrnchId"`
}

// BranchData3 ...
type BranchData3 struct {
	Id      string           `xml:"Id"`
	LEI     string           `xml:"LEI"`
	Nm      string           `xml:"Nm"`
	PstlAdr *PostalAddress24 `xml:"PstlAdr"`
}

// ClearingSystemIdentification2Choice ...
type ClearingSystemIdentification2Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// ClearingSystemMemberIdentification2 ...
type ClearingSystemMemberIdentification2 struct {
	ClrSysId *ClearingSystemIdentification2Choice `xml:"ClrSysId"`
	MmbId    string                               `xml:"MmbId"`
}

// CountryCode ...
type CountryCode string

// CreditDebitCode ...
type CreditDebitCode string

// DateAndPeriod2Choice ...
type DateAndPeriod2Choice struct {
	Dt   string   `xml:"Dt"`
	Prd  *Period2 `xml:"Prd"`
	FrDt string   `xml:"FrDt"`
	ToDt string   `xml:"ToDt"`
}

// Exact4AlphaNumericText ...
type Exact4AlphaNumericText string

// ExternalAccountIdentification1Code ...
type ExternalAccountIdentification1Code string

// ExternalClearingSystemIdentification1Code ...
type ExternalClearingSystemIdentification1Code string

// ExternalEnquiryRequestType1Code ...
type ExternalEnquiryRequestType1Code string

// ExternalFinancialInstitutionIdentification1Code ...
type ExternalFinancialInstitutionIdentification1Code string

// ExternalMarketInfrastructure1Code ...
type ExternalMarketInfrastructure1Code string

// ExternalPaymentControlRequestType1Code ...
type ExternalPaymentControlRequestType1Code string

// FinancialIdentificationSchemeName1Choice ...
type FinancialIdentificationSchemeName1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// FinancialInstitutionIdentification18 ...
type FinancialInstitutionIdentification18 struct {
	BICFI       string                               `xml:"BICFI"`
	ClrSysMmbId *ClearingSystemMemberIdentification2 `xml:"ClrSysMmbId"`
	LEI         string                               `xml:"LEI"`
	Nm          string                               `xml:"Nm"`
	PstlAdr     *PostalAddress24                     `xml:"PstlAdr"`
	Othr        *GenericFinancialIdentification1     `xml:"Othr"`
}

// FromToAmountRange1 ...
type FromToAmountRange1 struct {
	FrAmt *AmountRangeBoundary1 `xml:"FrAmt"`
	ToAmt *AmountRangeBoundary1 `xml:"ToAmt"`
}

// FromToPercentageRange1 ...
type FromToPercentageRange1 struct {
	Fr *PercentageRangeBoundary1 `xml:"Fr"`
	To *PercentageRangeBoundary1 `xml:"To"`
}

// GenericAccountIdentification1 ...
type GenericAccountIdentification1 struct {
	Id      string                    `xml:"Id"`
	SchmeNm *AccountSchemeName1Choice `xml:"SchmeNm"`
	Issr    string                    `xml:"Issr"`
}

// GenericFinancialIdentification1 ...
type GenericFinancialIdentification1 struct {
	Id      string                                    `xml:"Id"`
	SchmeNm *FinancialIdentificationSchemeName1Choice `xml:"SchmeNm"`
	Issr    string                                    `xml:"Issr"`
}

// GenericIdentification1 ...
type GenericIdentification1 struct {
	Id      string `xml:"Id"`
	SchmeNm string `xml:"SchmeNm"`
	Issr    string `xml:"Issr"`
}

// GenericIdentification30 ...
type GenericIdentification30 struct {
	Id      string `xml:"Id"`
	Issr    string `xml:"Issr"`
	SchmeNm string `xml:"SchmeNm"`
}

// GetLimitV07 ...
type GetLimitV07 struct {
	MsgHdr      *MessageHeader9       `xml:"MsgHdr"`
	LmtQryDef   *LimitQuery4          `xml:"LmtQryDef"`
	SplmtryData []*SupplementaryData1 `xml:"SplmtryData"`
}

// IBAN2007Identifier ...
type IBAN2007Identifier string

// ISODate ...
type ISODate string

// ISODateTime ...
type ISODateTime string

// ImpliedCurrencyAmountRange1Choice ...
type ImpliedCurrencyAmountRange1Choice struct {
	FrAmt   *AmountRangeBoundary1 `xml:"FrAmt"`
	ToAmt   *AmountRangeBoundary1 `xml:"ToAmt"`
	FrToAmt *FromToAmountRange1   `xml:"FrToAmt"`
	EQAmt   float64               `xml:"EQAmt"`
	NEQAmt  float64               `xml:"NEQAmt"`
}

// ImpliedCurrencyAndAmount ...
type ImpliedCurrencyAndAmount float64

// ImpliedCurrencyAndAmountRange1 ...
type ImpliedCurrencyAndAmountRange1 struct {
	Amt       *ImpliedCurrencyAmountRange1Choice `xml:"Amt"`
	CdtDbtInd string                             `xml:"CdtDbtInd"`
}

// LEIIdentifier ...
type LEIIdentifier string

// LimitCriteria6 ...
type LimitCriteria6 struct {
	NewQryNm string                  `xml:"NewQryNm"`
	SchCrit  []*LimitSearchCriteria6 `xml:"SchCrit"`
	RtrCrit  *LimitReturnCriteria2   `xml:"RtrCrit"`
}

// LimitCriteria6Choice ...
type LimitCriteria6Choice struct {
	QryNm   string          `xml:"QryNm"`
	NewCrit *LimitCriteria6 `xml:"NewCrit"`
}

// LimitQuery4 ...
type LimitQuery4 struct {
	QryTp   string                `xml:"QryTp"`
	LmtCrit *LimitCriteria6Choice `xml:"LmtCrit"`
}

// LimitReturnCriteria2 ...
type LimitReturnCriteria2 struct {
	StartDtTmInd bool `xml:"StartDtTmInd"`
	StsInd       bool `xml:"StsInd"`
	UsdAmtInd    bool `xml:"UsdAmtInd"`
	UsdPctgInd   bool `xml:"UsdPctgInd"`
}

// LimitSearchCriteria6 ...
type LimitSearchCriteria6 struct {
	SysId          *SystemIdentification2Choice                    `xml:"SysId"`
	BilLmtCtrPtyId []*BranchAndFinancialInstitutionIdentification6 `xml:"BilLmtCtrPtyId"`
	DfltLmtTp      []*LimitType1Choice                             `xml:"DfltLmtTp"`
	CurLmtTp       []*LimitType1Choice                             `xml:"CurLmtTp"`
	AcctOwnr       *BranchAndFinancialInstitutionIdentification6   `xml:"AcctOwnr"`
	AcctId         *AccountIdentification4Choice                   `xml:"AcctId"`
	UsdAmt         *ActiveAmountRange3Choice                       `xml:"UsdAmt"`
	UsdPctg        *PercentageRange1Choice                         `xml:"UsdPctg"`
	LmtCcy         string                                          `xml:"LmtCcy"`
	LmtAmt         *ActiveAmountRange3Choice                       `xml:"LmtAmt"`
	LmtVldAsOfDt   *DateAndPeriod2Choice                           `xml:"LmtVldAsOfDt"`
}

// LimitType1Choice ...
type LimitType1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// LimitType3Code ...
type LimitType3Code string

// MarketInfrastructureIdentification1Choice ...
type MarketInfrastructureIdentification1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// Max140Text ...
type Max140Text string

// Max16Text ...
type Max16Text string

// Max34Text ...
type Max34Text string

// Max350Text ...
type Max350Text string

// Max35Text ...
type Max35Text string

// Max70Text ...
type Max70Text string

// MessageHeader9 ...
type MessageHeader9 struct {
	MsgId   string              `xml:"MsgId"`
	CreDtTm string              `xml:"CreDtTm"`
	ReqTp   *RequestType4Choice `xml:"ReqTp"`
}

// PercentageRange1Choice ...
type PercentageRange1Choice struct {
	Fr   *PercentageRangeBoundary1 `xml:"Fr"`
	To   *PercentageRangeBoundary1 `xml:"To"`
	FrTo *FromToPercentageRange1   `xml:"FrTo"`
	EQ   float64                   `xml:"EQ"`
	NEQ  float64                   `xml:"NEQ"`
}

// PercentageRangeBoundary1 ...
type PercentageRangeBoundary1 struct {
	BdryRate float64 `xml:"BdryRate"`
	Incl     bool    `xml:"Incl"`
}

// PercentageRate ...
type PercentageRate float64

// Period2 ...
type Period2 struct {
	FrDt string `xml:"FrDt"`
	ToDt string `xml:"ToDt"`
}

// PostalAddress24 ...
type PostalAddress24 struct {
	AdrTp       *AddressType3Choice `xml:"AdrTp"`
	Dept        string              `xml:"Dept"`
	SubDept     string              `xml:"SubDept"`
	StrtNm      string              `xml:"StrtNm"`
	BldgNb      string              `xml:"BldgNb"`
	BldgNm      string              `xml:"BldgNm"`
	Flr         string              `xml:"Flr"`
	PstBx       string              `xml:"PstBx"`
	Room        string              `xml:"Room"`
	PstCd       string              `xml:"PstCd"`
	TwnNm       string              `xml:"TwnNm"`
	TwnLctnNm   string              `xml:"TwnLctnNm"`
	DstrctNm    string              `xml:"DstrctNm"`
	CtrySubDvsn string              `xml:"CtrySubDvsn"`
	Ctry        string              `xml:"Ctry"`
	AdrLine     []string            `xml:"AdrLine"`
}

// QueryType2Code ...
type QueryType2Code string

// RequestType4Choice ...
type RequestType4Choice struct {
	PmtCtrl string                  `xml:"PmtCtrl"`
	Enqry   string                  `xml:"Enqry"`
	Prtry   *GenericIdentification1 `xml:"Prtry"`
}

// RequestedIndicator ...
type RequestedIndicator bool

// SupplementaryData1 ...
type SupplementaryData1 struct {
	PlcAndNm string                      `xml:"PlcAndNm"`
	Envlp    *SupplementaryDataEnvelope1 `xml:"Envlp"`
}

// SupplementaryDataEnvelope1 ...
type SupplementaryDataEnvelope1 struct {
}

// SystemIdentification2Choice ...
type SystemIdentification2Choice struct {
	MktInfrstrctrId *MarketInfrastructureIdentification1Choice `xml:"MktInfrstrctrId"`
	Ctry            string                                     `xml:"Ctry"`
}

// YesNoIndicator ...
type YesNoIndicator bool
