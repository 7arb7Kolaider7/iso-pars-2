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

// AddressType2Code ...
type AddressType2Code string

// AddressType3Choice ...
type AddressType3Choice struct {
	Cd    string                   `xml:"Cd"`
	Prtry *GenericIdentification30 `xml:"Prtry"`
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

// GetReservationV05 ...
type GetReservationV05 struct {
	MsgHdr       *MessageHeader9       `xml:"MsgHdr"`
	RsvatnQryDef *ReservationQuery3    `xml:"RsvatnQryDef"`
	SplmtryData  []*SupplementaryData1 `xml:"SplmtryData"`
}

// IBAN2007Identifier ...
type IBAN2007Identifier string

// ISODateTime ...
type ISODateTime string

// LEIIdentifier ...
type LEIIdentifier string

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

// ReservationCriteria3Choice ...
type ReservationCriteria3Choice struct {
	QryNm   string                `xml:"QryNm"`
	NewCrit *ReservationCriteria4 `xml:"NewCrit"`
}

// ReservationCriteria4 ...
type ReservationCriteria4 struct {
	NewQryNm string                        `xml:"NewQryNm"`
	SchCrit  []*ReservationSearchCriteria3 `xml:"SchCrit"`
	RtrCrit  *ReservationReturnCriteria1   `xml:"RtrCrit"`
}

// ReservationQuery3 ...
type ReservationQuery3 struct {
	QryTp      string                      `xml:"QryTp"`
	RsvatnCrit *ReservationCriteria3Choice `xml:"RsvatnCrit"`
}

// ReservationReturnCriteria1 ...
type ReservationReturnCriteria1 struct {
	StartDtTmInd bool `xml:"StartDtTmInd"`
	StsInd       bool `xml:"StsInd"`
}

// ReservationSearchCriteria3 ...
type ReservationSearchCriteria3 struct {
	SysId        *SystemIdentification2Choice                  `xml:"SysId"`
	DfltRsvatnTp []string                                      `xml:"DfltRsvatnTp"`
	CurRsvatnTp  []string                                      `xml:"CurRsvatnTp"`
	AcctOwnr     *BranchAndFinancialInstitutionIdentification6 `xml:"AcctOwnr"`
	AcctId       *AccountIdentification4Choice                 `xml:"AcctId"`
}

// ReservationType1Code ...
type ReservationType1Code string

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
