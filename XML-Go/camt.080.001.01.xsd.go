package schema

// Document ...
type Document *Document

// AccountIdentification4Choice ...
type AccountIdentification4Choice struct {
	IBAN string                         `xml:"IBAN"`
	Othr *GenericAccountIdentification1 `xml:"Othr"`
}

// AccountIdentificationSearchCriteria2Choice ...
type AccountIdentificationSearchCriteria2Choice struct {
	EQ     *AccountIdentification4Choice `xml:"EQ"`
	CTTxt  string                        `xml:"CTTxt"`
	NCTTxt string                        `xml:"NCTTxt"`
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

// AnyBICDec2014Identifier ...
type AnyBICDec2014Identifier string

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

// CopyDuplicate1Code ...
type CopyDuplicate1Code string

// CountryCode ...
type CountryCode string

// DateAndDateTime2Choice ...
type DateAndDateTime2Choice struct {
	Dt   string `xml:"Dt"`
	DtTm string `xml:"DtTm"`
}

// DateAndDateTimeSearch5Choice ...
type DateAndDateTimeSearch5Choice struct {
	Dt   *DatePeriodSearch1Choice `xml:"Dt"`
	DtTm *DateTimeSearch2Choice   `xml:"DtTm"`
}

// DatePeriod2 ...
type DatePeriod2 struct {
	FrDt string `xml:"FrDt"`
	ToDt string `xml:"ToDt"`
}

// DatePeriodSearch1Choice ...
type DatePeriodSearch1Choice struct {
	FrDt   string       `xml:"FrDt"`
	ToDt   string       `xml:"ToDt"`
	FrToDt *DatePeriod2 `xml:"FrToDt"`
	EQDt   string       `xml:"EQDt"`
	NEQDt  string       `xml:"NEQDt"`
}

// DateTimePeriod1 ...
type DateTimePeriod1 struct {
	FrDtTm string `xml:"FrDtTm"`
	ToDtTm string `xml:"ToDtTm"`
}

// DateTimeSearch2Choice ...
type DateTimeSearch2Choice struct {
	FrDtTm   string           `xml:"FrDtTm"`
	ToDtTm   string           `xml:"ToDtTm"`
	FrToDtTm *DateTimePeriod1 `xml:"FrToDtTm"`
	EQDtTm   string           `xml:"EQDtTm"`
	NEQDtTm  string           `xml:"NEQDtTm"`
}

// DocumentIdentification51 ...
type DocumentIdentification51 struct {
	Id       string                  `xml:"Id"`
	CreDtTm  *DateAndDateTime2Choice `xml:"CreDtTm"`
	CpyDplct string                  `xml:"CpyDplct"`
	MsgOrgtr *PartyIdentification136 `xml:"MsgOrgtr"`
	MsgRcpt  *PartyIdentification136 `xml:"MsgRcpt"`
}

// Exact4AlphaNumericText ...
type Exact4AlphaNumericText string

// ExternalAccountIdentification1Code ...
type ExternalAccountIdentification1Code string

// ExternalClearingSystemIdentification1Code ...
type ExternalClearingSystemIdentification1Code string

// ExternalFinancialInstitutionIdentification1Code ...
type ExternalFinancialInstitutionIdentification1Code string

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

// GenericIdentification30 ...
type GenericIdentification30 struct {
	Id      string `xml:"Id"`
	Issr    string `xml:"Issr"`
	SchmeNm string `xml:"SchmeNm"`
}

// GenericIdentification36 ...
type GenericIdentification36 struct {
	Id      string `xml:"Id"`
	Issr    string `xml:"Issr"`
	SchmeNm string `xml:"SchmeNm"`
}

// IBAN2007Identifier ...
type IBAN2007Identifier string

// ISODate ...
type ISODate string

// ISODateTime ...
type ISODateTime string

// IntraBalanceMovementModificationQueryV01 ...
type IntraBalanceMovementModificationQueryV01 struct {
	Id          *DocumentIdentification51     `xml:"Id"`
	QryDef      *IntraBalanceQueryDefinition8 `xml:"QryDef"`
	SplmtryData []*SupplementaryData1         `xml:"SplmtryData"`
}

// IntraBalanceQueryCriteria8 ...
type IntraBalanceQueryCriteria8 struct {
	ModReqId    []string                                      `xml:"ModReqId"`
	PrcgSts     []*ModificationProcessingStatus9Choice        `xml:"PrcgSts"`
	CshAcct     []*AccountIdentificationSearchCriteria2Choice `xml:"CshAcct"`
	CshAcctOwnr []*SystemPartyIdentification8                 `xml:"CshAcctOwnr"`
	CshAcctSvcr *BranchAndFinancialInstitutionIdentification6 `xml:"CshAcctSvcr"`
	MsgOrgtr    []*SystemPartyIdentification8                 `xml:"MsgOrgtr"`
	CreDtTm     *DateAndDateTimeSearch5Choice                 `xml:"CreDtTm"`
}

// IntraBalanceQueryDefinition8 ...
type IntraBalanceQueryDefinition8 struct {
	QryTp   string                      `xml:"QryTp"`
	SchCrit *IntraBalanceQueryCriteria8 `xml:"SchCrit"`
}

// LEIIdentifier ...
type LEIIdentifier string

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

// ModificationProcessingStatus1Code ...
type ModificationProcessingStatus1Code string

// ModificationProcessingStatus9Choice ...
type ModificationProcessingStatus9Choice struct {
	Cd    string                   `xml:"Cd"`
	Prtry *GenericIdentification30 `xml:"Prtry"`
}

// MovementResponseType1Code ...
type MovementResponseType1Code string

// NameAndAddress5 ...
type NameAndAddress5 struct {
	Nm  string          `xml:"Nm"`
	Adr *PostalAddress1 `xml:"Adr"`
}

// PartyIdentification120Choice ...
type PartyIdentification120Choice struct {
	AnyBIC   string                   `xml:"AnyBIC"`
	PrtryId  *GenericIdentification36 `xml:"PrtryId"`
	NmAndAdr *NameAndAddress5         `xml:"NmAndAdr"`
}

// PartyIdentification136 ...
type PartyIdentification136 struct {
	Id  *PartyIdentification120Choice `xml:"Id"`
	LEI string                        `xml:"LEI"`
}

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

// SupplementaryData1 ...
type SupplementaryData1 struct {
	PlcAndNm string                      `xml:"PlcAndNm"`
	Envlp    *SupplementaryDataEnvelope1 `xml:"Envlp"`
}

// SupplementaryDataEnvelope1 ...
type SupplementaryDataEnvelope1 struct {
}

// SystemPartyIdentification8 ...
type SystemPartyIdentification8 struct {
	Id           *PartyIdentification136 `xml:"Id"`
	RspnsblPtyId *PartyIdentification136 `xml:"RspnsblPtyId"`
}
