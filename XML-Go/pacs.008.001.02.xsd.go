package schema

import (
	"time"
)

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

// ActiveCurrencyAndAmountSimpleType ...
type ActiveCurrencyAndAmountSimpleType float64

// ActiveCurrencyAndAmount ...
type ActiveCurrencyAndAmount struct {
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

// AddressType2Code ...
type AddressType2Code string

// AnyBICIdentifier ...
type AnyBICIdentifier string

// BICIdentifier ...
type BICIdentifier string

// BaseOneRate ...
type BaseOneRate float64

// BatchBookingIndicator ...
type BatchBookingIndicator bool

// BranchAndFinancialInstitutionIdentification4 ...
type BranchAndFinancialInstitutionIdentification4 struct {
	FinInstnId *FinancialInstitutionIdentification7 `xml:"FinInstnId"`
	BrnchId    *BranchData2                         `xml:"BrnchId"`
}

// BranchData2 ...
type BranchData2 struct {
	Id      string          `xml:"Id"`
	Nm      string          `xml:"Nm"`
	PstlAdr *PostalAddress6 `xml:"PstlAdr"`
}

// CashAccount16 ...
type CashAccount16 struct {
	Id  *AccountIdentification4Choice `xml:"Id"`
	Tp  *CashAccountType2             `xml:"Tp"`
	Ccy string                        `xml:"Ccy"`
	Nm  string                        `xml:"Nm"`
}

// CashAccountType2 ...
type CashAccountType2 struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// CashAccountType4Code ...
type CashAccountType4Code string

// CategoryPurpose1Choice ...
type CategoryPurpose1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// ChargeBearerType1Code ...
type ChargeBearerType1Code string

// ChargesInformation5 ...
type ChargesInformation5 struct {
	Amt *ActiveOrHistoricCurrencyAndAmount            `xml:"Amt"`
	Pty *BranchAndFinancialInstitutionIdentification4 `xml:"Pty"`
}

// ClearingChannel2Code ...
type ClearingChannel2Code string

// ClearingSystemIdentification2Choice ...
type ClearingSystemIdentification2Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// ClearingSystemIdentification3Choice ...
type ClearingSystemIdentification3Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// ClearingSystemMemberIdentification2 ...
type ClearingSystemMemberIdentification2 struct {
	ClrSysId *ClearingSystemIdentification2Choice `xml:"ClrSysId"`
	MmbId    string                               `xml:"MmbId"`
}

// ContactDetails2 ...
type ContactDetails2 struct {
	NmPrfx   string `xml:"NmPrfx"`
	Nm       string `xml:"Nm"`
	PhneNb   string `xml:"PhneNb"`
	MobNb    string `xml:"MobNb"`
	FaxNb    string `xml:"FaxNb"`
	EmailAdr string `xml:"EmailAdr"`
	Othr     string `xml:"Othr"`
}

// CountryCode ...
type CountryCode string

// CreditDebitCode ...
type CreditDebitCode string

// CreditTransferTransactionInformation11 ...
type CreditTransferTransactionInformation11 struct {
	PmtId            *PaymentIdentification3                       `xml:"PmtId"`
	PmtTpInf         *PaymentTypeInformation21                     `xml:"PmtTpInf"`
	IntrBkSttlmAmt   *ActiveCurrencyAndAmount                      `xml:"IntrBkSttlmAmt"`
	IntrBkSttlmDt    string                                        `xml:"IntrBkSttlmDt"`
	SttlmPrty        string                                        `xml:"SttlmPrty"`
	SttlmTmIndctn    *SettlementDateTimeIndication1                `xml:"SttlmTmIndctn"`
	SttlmTmReq       *SettlementTimeRequest2                       `xml:"SttlmTmReq"`
	AccptncDtTm      string                                        `xml:"AccptncDtTm"`
	PoolgAdjstmntDt  string                                        `xml:"PoolgAdjstmntDt"`
	InstdAmt         *ActiveOrHistoricCurrencyAndAmount            `xml:"InstdAmt"`
	XchgRate         float64                                       `xml:"XchgRate"`
	ChrgBr           string                                        `xml:"ChrgBr"`
	ChrgsInf         []*ChargesInformation5                        `xml:"ChrgsInf"`
	PrvsInstgAgt     *BranchAndFinancialInstitutionIdentification4 `xml:"PrvsInstgAgt"`
	PrvsInstgAgtAcct *CashAccount16                                `xml:"PrvsInstgAgtAcct"`
	InstgAgt         *BranchAndFinancialInstitutionIdentification4 `xml:"InstgAgt"`
	InstdAgt         *BranchAndFinancialInstitutionIdentification4 `xml:"InstdAgt"`
	IntrmyAgt1       *BranchAndFinancialInstitutionIdentification4 `xml:"IntrmyAgt1"`
	IntrmyAgt1Acct   *CashAccount16                                `xml:"IntrmyAgt1Acct"`
	IntrmyAgt2       *BranchAndFinancialInstitutionIdentification4 `xml:"IntrmyAgt2"`
	IntrmyAgt2Acct   *CashAccount16                                `xml:"IntrmyAgt2Acct"`
	IntrmyAgt3       *BranchAndFinancialInstitutionIdentification4 `xml:"IntrmyAgt3"`
	IntrmyAgt3Acct   *CashAccount16                                `xml:"IntrmyAgt3Acct"`
	UltmtDbtr        *PartyIdentification32                        `xml:"UltmtDbtr"`
	InitgPty         *PartyIdentification32                        `xml:"InitgPty"`
	Dbtr             *PartyIdentification32                        `xml:"Dbtr"`
	DbtrAcct         *CashAccount16                                `xml:"DbtrAcct"`
	DbtrAgt          *BranchAndFinancialInstitutionIdentification4 `xml:"DbtrAgt"`
	DbtrAgtAcct      *CashAccount16                                `xml:"DbtrAgtAcct"`
	CdtrAgt          *BranchAndFinancialInstitutionIdentification4 `xml:"CdtrAgt"`
	CdtrAgtAcct      *CashAccount16                                `xml:"CdtrAgtAcct"`
	Cdtr             *PartyIdentification32                        `xml:"Cdtr"`
	CdtrAcct         *CashAccount16                                `xml:"CdtrAcct"`
	UltmtCdtr        *PartyIdentification32                        `xml:"UltmtCdtr"`
	InstrForCdtrAgt  []*InstructionForCreditorAgent1               `xml:"InstrForCdtrAgt"`
	InstrForNxtAgt   []*InstructionForNextAgent1                   `xml:"InstrForNxtAgt"`
	Purp             *Purpose2Choice                               `xml:"Purp"`
	RgltryRptg       []*RegulatoryReporting3                       `xml:"RgltryRptg"`
	RltdRmtInf       []*RemittanceLocation2                        `xml:"RltdRmtInf"`
	RmtInf           *RemittanceInformation5                       `xml:"RmtInf"`
}

// CreditorReferenceInformation2 ...
type CreditorReferenceInformation2 struct {
	Tp  *CreditorReferenceType2 `xml:"Tp"`
	Ref string                  `xml:"Ref"`
}

// CreditorReferenceType1Choice ...
type CreditorReferenceType1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// CreditorReferenceType2 ...
type CreditorReferenceType2 struct {
	CdOrPrtry *CreditorReferenceType1Choice `xml:"CdOrPrtry"`
	Issr      string                        `xml:"Issr"`
}

// DateAndPlaceOfBirth ...
type DateAndPlaceOfBirth struct {
	BirthDt     string `xml:"BirthDt"`
	PrvcOfBirth string `xml:"PrvcOfBirth"`
	CityOfBirth string `xml:"CityOfBirth"`
	CtryOfBirth string `xml:"CtryOfBirth"`
}

// DecimalNumber ...
type DecimalNumber float64

// DocumentAdjustment1 ...
type DocumentAdjustment1 struct {
	Amt       *ActiveOrHistoricCurrencyAndAmount `xml:"Amt"`
	CdtDbtInd string                             `xml:"CdtDbtInd"`
	Rsn       string                             `xml:"Rsn"`
	AddtlInf  string                             `xml:"AddtlInf"`
}

// DocumentType3Code ...
type DocumentType3Code string

// DocumentType5Code ...
type DocumentType5Code string

// ExternalAccountIdentification1Code ...
type ExternalAccountIdentification1Code string

// ExternalCashClearingSystem1Code ...
type ExternalCashClearingSystem1Code string

// ExternalCategoryPurpose1Code ...
type ExternalCategoryPurpose1Code string

// ExternalClearingSystemIdentification1Code ...
type ExternalClearingSystemIdentification1Code string

// ExternalFinancialInstitutionIdentification1Code ...
type ExternalFinancialInstitutionIdentification1Code string

// ExternalLocalInstrument1Code ...
type ExternalLocalInstrument1Code string

// ExternalOrganisationIdentification1Code ...
type ExternalOrganisationIdentification1Code string

// ExternalPersonIdentification1Code ...
type ExternalPersonIdentification1Code string

// ExternalPurpose1Code ...
type ExternalPurpose1Code string

// ExternalServiceLevel1Code ...
type ExternalServiceLevel1Code string

// FIToFICustomerCreditTransferV02 ...
type FIToFICustomerCreditTransferV02 struct {
	GrpHdr      *GroupHeader33                            `xml:"GrpHdr"`
	CdtTrfTxInf []*CreditTransferTransactionInformation11 `xml:"CdtTrfTxInf"`
}

// FinancialIdentificationSchemeName1Choice ...
type FinancialIdentificationSchemeName1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// FinancialInstitutionIdentification7 ...
type FinancialInstitutionIdentification7 struct {
	BIC         string                               `xml:"BIC"`
	ClrSysMmbId *ClearingSystemMemberIdentification2 `xml:"ClrSysMmbId"`
	Nm          string                               `xml:"Nm"`
	PstlAdr     *PostalAddress6                      `xml:"PstlAdr"`
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

// GenericOrganisationIdentification1 ...
type GenericOrganisationIdentification1 struct {
	Id      string                                       `xml:"Id"`
	SchmeNm *OrganisationIdentificationSchemeName1Choice `xml:"SchmeNm"`
	Issr    string                                       `xml:"Issr"`
}

// GenericPersonIdentification1 ...
type GenericPersonIdentification1 struct {
	Id      string                                 `xml:"Id"`
	SchmeNm *PersonIdentificationSchemeName1Choice `xml:"SchmeNm"`
	Issr    string                                 `xml:"Issr"`
}

// GroupHeader33 ...
type GroupHeader33 struct {
	MsgId             string                                        `xml:"MsgId"`
	CreDtTm           string                                        `xml:"CreDtTm"`
	BtchBookg         bool                                          `xml:"BtchBookg"`
	NbOfTxs           string                                        `xml:"NbOfTxs"`
	CtrlSum           float64                                       `xml:"CtrlSum"`
	TtlIntrBkSttlmAmt *ActiveCurrencyAndAmount                      `xml:"TtlIntrBkSttlmAmt"`
	IntrBkSttlmDt     string                                        `xml:"IntrBkSttlmDt"`
	SttlmInf          *SettlementInformation13                      `xml:"SttlmInf"`
	PmtTpInf          *PaymentTypeInformation21                     `xml:"PmtTpInf"`
	InstgAgt          *BranchAndFinancialInstitutionIdentification4 `xml:"InstgAgt"`
	InstdAgt          *BranchAndFinancialInstitutionIdentification4 `xml:"InstdAgt"`
}

// IBAN2007Identifier ...
type IBAN2007Identifier string

// ISODate ...
type ISODate string

// ISODateTime ...
type ISODateTime string

// ISOTime ...
type ISOTime time.Time

// Instruction3Code ...
type Instruction3Code string

// Instruction4Code ...
type Instruction4Code string

// InstructionForCreditorAgent1 ...
type InstructionForCreditorAgent1 struct {
	Cd       string `xml:"Cd"`
	InstrInf string `xml:"InstrInf"`
}

// InstructionForNextAgent1 ...
type InstructionForNextAgent1 struct {
	Cd       string `xml:"Cd"`
	InstrInf string `xml:"InstrInf"`
}

// LocalInstrument2Choice ...
type LocalInstrument2Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// Max10Text ...
type Max10Text string

// Max140Text ...
type Max140Text string

// Max15NumericText ...
type Max15NumericText string

// Max16Text ...
type Max16Text string

// Max2048Text ...
type Max2048Text string

// Max34Text ...
type Max34Text string

// Max35Text ...
type Max35Text string

// Max4Text ...
type Max4Text string

// Max70Text ...
type Max70Text string

// NameAndAddress10 ...
type NameAndAddress10 struct {
	Nm  string          `xml:"Nm"`
	Adr *PostalAddress6 `xml:"Adr"`
}

// NamePrefix1Code ...
type NamePrefix1Code string

// OrganisationIdentification4 ...
type OrganisationIdentification4 struct {
	BICOrBEI string                                `xml:"BICOrBEI"`
	Othr     []*GenericOrganisationIdentification1 `xml:"Othr"`
}

// OrganisationIdentificationSchemeName1Choice ...
type OrganisationIdentificationSchemeName1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// Party6Choice ...
type Party6Choice struct {
	OrgId  *OrganisationIdentification4 `xml:"OrgId"`
	PrvtId *PersonIdentification5       `xml:"PrvtId"`
}

// PartyIdentification32 ...
type PartyIdentification32 struct {
	Nm        string           `xml:"Nm"`
	PstlAdr   *PostalAddress6  `xml:"PstlAdr"`
	Id        *Party6Choice    `xml:"Id"`
	CtryOfRes string           `xml:"CtryOfRes"`
	CtctDtls  *ContactDetails2 `xml:"CtctDtls"`
}

// PaymentIdentification3 ...
type PaymentIdentification3 struct {
	InstrId    string `xml:"InstrId"`
	EndToEndId string `xml:"EndToEndId"`
	TxId       string `xml:"TxId"`
	ClrSysRef  string `xml:"ClrSysRef"`
}

// PaymentTypeInformation21 ...
type PaymentTypeInformation21 struct {
	InstrPrty string                  `xml:"InstrPrty"`
	ClrChanl  string                  `xml:"ClrChanl"`
	SvcLvl    *ServiceLevel8Choice    `xml:"SvcLvl"`
	LclInstrm *LocalInstrument2Choice `xml:"LclInstrm"`
	CtgyPurp  *CategoryPurpose1Choice `xml:"CtgyPurp"`
}

// PersonIdentification5 ...
type PersonIdentification5 struct {
	DtAndPlcOfBirth *DateAndPlaceOfBirth            `xml:"DtAndPlcOfBirth"`
	Othr            []*GenericPersonIdentification1 `xml:"Othr"`
}

// PersonIdentificationSchemeName1Choice ...
type PersonIdentificationSchemeName1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// PhoneNumber ...
type PhoneNumber string

// PostalAddress6 ...
type PostalAddress6 struct {
	AdrTp       string   `xml:"AdrTp"`
	Dept        string   `xml:"Dept"`
	SubDept     string   `xml:"SubDept"`
	StrtNm      string   `xml:"StrtNm"`
	BldgNb      string   `xml:"BldgNb"`
	PstCd       string   `xml:"PstCd"`
	TwnNm       string   `xml:"TwnNm"`
	CtrySubDvsn string   `xml:"CtrySubDvsn"`
	Ctry        string   `xml:"Ctry"`
	AdrLine     []string `xml:"AdrLine"`
}

// Priority2Code ...
type Priority2Code string

// Priority3Code ...
type Priority3Code string

// Purpose2Choice ...
type Purpose2Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// ReferredDocumentInformation3 ...
type ReferredDocumentInformation3 struct {
	Tp     *ReferredDocumentType2 `xml:"Tp"`
	Nb     string                 `xml:"Nb"`
	RltdDt string                 `xml:"RltdDt"`
}

// ReferredDocumentType1Choice ...
type ReferredDocumentType1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// ReferredDocumentType2 ...
type ReferredDocumentType2 struct {
	CdOrPrtry *ReferredDocumentType1Choice `xml:"CdOrPrtry"`
	Issr      string                       `xml:"Issr"`
}

// RegulatoryAuthority2 ...
type RegulatoryAuthority2 struct {
	Nm   string `xml:"Nm"`
	Ctry string `xml:"Ctry"`
}

// RegulatoryReporting3 ...
type RegulatoryReporting3 struct {
	DbtCdtRptgInd string                            `xml:"DbtCdtRptgInd"`
	Authrty       *RegulatoryAuthority2             `xml:"Authrty"`
	Dtls          []*StructuredRegulatoryReporting3 `xml:"Dtls"`
}

// RegulatoryReportingType1Code ...
type RegulatoryReportingType1Code string

// RemittanceAmount1 ...
type RemittanceAmount1 struct {
	DuePyblAmt        *ActiveOrHistoricCurrencyAndAmount `xml:"DuePyblAmt"`
	DscntApldAmt      *ActiveOrHistoricCurrencyAndAmount `xml:"DscntApldAmt"`
	CdtNoteAmt        *ActiveOrHistoricCurrencyAndAmount `xml:"CdtNoteAmt"`
	TaxAmt            *ActiveOrHistoricCurrencyAndAmount `xml:"TaxAmt"`
	AdjstmntAmtAndRsn []*DocumentAdjustment1             `xml:"AdjstmntAmtAndRsn"`
	RmtdAmt           *ActiveOrHistoricCurrencyAndAmount `xml:"RmtdAmt"`
}

// RemittanceInformation5 ...
type RemittanceInformation5 struct {
	Ustrd []string                            `xml:"Ustrd"`
	Strd  []*StructuredRemittanceInformation7 `xml:"Strd"`
}

// RemittanceLocation2 ...
type RemittanceLocation2 struct {
	RmtId             string            `xml:"RmtId"`
	RmtLctnMtd        string            `xml:"RmtLctnMtd"`
	RmtLctnElctrncAdr string            `xml:"RmtLctnElctrncAdr"`
	RmtLctnPstlAdr    *NameAndAddress10 `xml:"RmtLctnPstlAdr"`
}

// RemittanceLocationMethod2Code ...
type RemittanceLocationMethod2Code string

// ServiceLevel8Choice ...
type ServiceLevel8Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// SettlementDateTimeIndication1 ...
type SettlementDateTimeIndication1 struct {
	DbtDtTm string `xml:"DbtDtTm"`
	CdtDtTm string `xml:"CdtDtTm"`
}

// SettlementInformation13 ...
type SettlementInformation13 struct {
	SttlmMtd             string                                        `xml:"SttlmMtd"`
	SttlmAcct            *CashAccount16                                `xml:"SttlmAcct"`
	ClrSys               *ClearingSystemIdentification3Choice          `xml:"ClrSys"`
	InstgRmbrsmntAgt     *BranchAndFinancialInstitutionIdentification4 `xml:"InstgRmbrsmntAgt"`
	InstgRmbrsmntAgtAcct *CashAccount16                                `xml:"InstgRmbrsmntAgtAcct"`
	InstdRmbrsmntAgt     *BranchAndFinancialInstitutionIdentification4 `xml:"InstdRmbrsmntAgt"`
	InstdRmbrsmntAgtAcct *CashAccount16                                `xml:"InstdRmbrsmntAgtAcct"`
	ThrdRmbrsmntAgt      *BranchAndFinancialInstitutionIdentification4 `xml:"ThrdRmbrsmntAgt"`
	ThrdRmbrsmntAgtAcct  *CashAccount16                                `xml:"ThrdRmbrsmntAgtAcct"`
}

// SettlementMethod1Code ...
type SettlementMethod1Code string

// SettlementTimeRequest2 ...
type SettlementTimeRequest2 struct {
	CLSTm  time.Time `xml:"CLSTm"`
	TillTm time.Time `xml:"TillTm"`
	FrTm   time.Time `xml:"FrTm"`
	RjctTm time.Time `xml:"RjctTm"`
}

// StructuredRegulatoryReporting3 ...
type StructuredRegulatoryReporting3 struct {
	Tp   string                             `xml:"Tp"`
	Dt   string                             `xml:"Dt"`
	Ctry string                             `xml:"Ctry"`
	Cd   string                             `xml:"Cd"`
	Amt  *ActiveOrHistoricCurrencyAndAmount `xml:"Amt"`
	Inf  []string                           `xml:"Inf"`
}

// StructuredRemittanceInformation7 ...
type StructuredRemittanceInformation7 struct {
	RfrdDocInf  []*ReferredDocumentInformation3 `xml:"RfrdDocInf"`
	RfrdDocAmt  *RemittanceAmount1              `xml:"RfrdDocAmt"`
	CdtrRefInf  *CreditorReferenceInformation2  `xml:"CdtrRefInf"`
	Invcr       *PartyIdentification32          `xml:"Invcr"`
	Invcee      *PartyIdentification32          `xml:"Invcee"`
	AddtlRmtInf []string                        `xml:"AddtlRmtInf"`
}
