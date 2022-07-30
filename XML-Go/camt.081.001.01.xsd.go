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

// AcknowledgedAcceptedStatus21Choice ...
type AcknowledgedAcceptedStatus21Choice struct {
	NoSpcfdRsn string                    `xml:"NoSpcfdRsn"`
	Rsn        []*AcknowledgementReason9 `xml:"Rsn"`
}

// AcknowledgementReason12Choice ...
type AcknowledgementReason12Choice struct {
	Cd    string                   `xml:"Cd"`
	Prtry *GenericIdentification30 `xml:"Prtry"`
}

// AcknowledgementReason5Code ...
type AcknowledgementReason5Code string

// AcknowledgementReason9 ...
type AcknowledgementReason9 struct {
	Cd          *AcknowledgementReason12Choice `xml:"Cd"`
	AddtlRsnInf string                         `xml:"AddtlRsnInf"`
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

// ActiveOrHistoricCurrencyCode ...
type ActiveOrHistoricCurrencyCode string

// AddressType2Code ...
type AddressType2Code string

// AddressType3Choice ...
type AddressType3Choice struct {
	Cd    string                   `xml:"Cd"`
	Prtry *GenericIdentification30 `xml:"Prtry"`
}

// Amount2Choice ...
type Amount2Choice struct {
	AmtWthtCcy float64                  `xml:"AmtWthtCcy"`
	AmtWthCcy  *ActiveCurrencyAndAmount `xml:"AmtWthCcy"`
}

// AmountAndDirection5 ...
type AmountAndDirection5 struct {
	Amt    *ActiveCurrencyAndAmount `xml:"Amt"`
	CdtDbt string                   `xml:"CdtDbt"`
}

// AmountAndQuantityBreakdown1 ...
type AmountAndQuantityBreakdown1 struct {
	LotNb       *GenericIdentification37            `xml:"LotNb"`
	LotAmt      *AmountAndDirection5                `xml:"LotAmt"`
	LotQty      *FinancialInstrumentQuantity1Choice `xml:"LotQty"`
	CshSubBalTp *GenericIdentification30            `xml:"CshSubBalTp"`
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

// CashAccount38 ...
type CashAccount38 struct {
	Id   *AccountIdentification4Choice `xml:"Id"`
	Tp   *CashAccountType2Choice       `xml:"Tp"`
	Ccy  string                        `xml:"Ccy"`
	Nm   string                        `xml:"Nm"`
	Prxy *ProxyAccountIdentification1  `xml:"Prxy"`
}

// CashAccountType2Choice ...
type CashAccountType2Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// CashBalanceType3Choice ...
type CashBalanceType3Choice struct {
	Cd    string                   `xml:"Cd"`
	Prtry *GenericIdentification30 `xml:"Prtry"`
}

// CashSubBalanceTypeAndQuantityBreakdown3 ...
type CashSubBalanceTypeAndQuantityBreakdown3 struct {
	Tp        *CashBalanceType3Choice        `xml:"Tp"`
	QtyBrkdwn []*AmountAndQuantityBreakdown1 `xml:"QtyBrkdwn"`
}

// ClearingChannel2Code ...
type ClearingChannel2Code string

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

// CreditDebitCode ...
type CreditDebitCode string

// DateAndDateTime2Choice ...
type DateAndDateTime2Choice struct {
	Dt   string `xml:"Dt"`
	DtTm string `xml:"DtTm"`
}

// DateTimePeriod1 ...
type DateTimePeriod1 struct {
	FrDtTm string `xml:"FrDtTm"`
	ToDtTm string `xml:"ToDtTm"`
}

// DecimalNumber ...
type DecimalNumber float64

// DeniedReason11 ...
type DeniedReason11 struct {
	Cd          *DeniedReason16Choice `xml:"Cd"`
	AddtlRsnInf string                `xml:"AddtlRsnInf"`
}

// DeniedReason16Choice ...
type DeniedReason16Choice struct {
	Cd    string                   `xml:"Cd"`
	Prtry *GenericIdentification30 `xml:"Prtry"`
}

// DeniedReason4Code ...
type DeniedReason4Code string

// DeniedStatus16Choice ...
type DeniedStatus16Choice struct {
	NoSpcfdRsn string            `xml:"NoSpcfdRsn"`
	Rsn        []*DeniedReason11 `xml:"Rsn"`
}

// DocumentIdentification51 ...
type DocumentIdentification51 struct {
	Id       string                  `xml:"Id"`
	CreDtTm  *DateAndDateTime2Choice `xml:"CreDtTm"`
	CpyDplct string                  `xml:"CpyDplct"`
	MsgOrgtr *PartyIdentification136 `xml:"MsgOrgtr"`
	MsgRcpt  *PartyIdentification136 `xml:"MsgRcpt"`
}

// DocumentNumber5Choice ...
type DocumentNumber5Choice struct {
	ShrtNb  string                   `xml:"ShrtNb"`
	LngNb   string                   `xml:"LngNb"`
	PrtryNb *GenericIdentification36 `xml:"PrtryNb"`
}

// ErrorHandling3Choice ...
type ErrorHandling3Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// ErrorHandling5 ...
type ErrorHandling5 struct {
	Err  *ErrorHandling3Choice `xml:"Err"`
	Desc string                `xml:"Desc"`
}

// EventFrequency7Code ...
type EventFrequency7Code string

// Exact3NumericText ...
type Exact3NumericText string

// Exact4AlphaNumericText ...
type Exact4AlphaNumericText string

// Exact4NumericText ...
type Exact4NumericText string

// Exact5NumericText ...
type Exact5NumericText string

// ExternalAccountIdentification1Code ...
type ExternalAccountIdentification1Code string

// ExternalBalanceType1Code ...
type ExternalBalanceType1Code string

// ExternalCashAccountType1Code ...
type ExternalCashAccountType1Code string

// ExternalClearingSystemIdentification1Code ...
type ExternalClearingSystemIdentification1Code string

// ExternalFinancialInstitutionIdentification1Code ...
type ExternalFinancialInstitutionIdentification1Code string

// ExternalProxyAccountType1Code ...
type ExternalProxyAccountType1Code string

// ExternalSystemErrorHandling1Code ...
type ExternalSystemErrorHandling1Code string

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

// FinancialInstrumentQuantity1Choice ...
type FinancialInstrumentQuantity1Choice struct {
	Unit     float64 `xml:"Unit"`
	FaceAmt  float64 `xml:"FaceAmt"`
	AmtsdVal float64 `xml:"AmtsdVal"`
}

// Frequency22Choice ...
type Frequency22Choice struct {
	Cd    string                   `xml:"Cd"`
	Prtry *GenericIdentification30 `xml:"Prtry"`
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

// GenericIdentification37 ...
type GenericIdentification37 struct {
	Id   string `xml:"Id"`
	Issr string `xml:"Issr"`
}

// IBAN2007Identifier ...
type IBAN2007Identifier string

// ISO20022MessageIdentificationText ...
type ISO20022MessageIdentificationText string

// ISODate ...
type ISODate string

// ISODateTime ...
type ISODateTime string

// ImpliedCurrencyAndAmount ...
type ImpliedCurrencyAndAmount float64

// IntraBalance5 ...
type IntraBalance5 struct {
	SttlmAmt           *Amount2Choice                           `xml:"SttlmAmt"`
	SttlmDt            *DateAndDateTime2Choice                  `xml:"SttlmDt"`
	BalFr              *CashSubBalanceTypeAndQuantityBreakdown3 `xml:"BalFr"`
	BalTo              *CashSubBalanceTypeAndQuantityBreakdown3 `xml:"BalTo"`
	CshSubBalId        *GenericIdentification37                 `xml:"CshSubBalId"`
	Prty               *PriorityNumeric4Choice                  `xml:"Prty"`
	InstrPrcgAddtlDtls string                                   `xml:"InstrPrcgAddtlDtls"`
}

// IntraBalanceModification5 ...
type IntraBalanceModification5 struct {
	CshAcct     *CashAccount38                                `xml:"CshAcct"`
	CshAcctOwnr *SystemPartyIdentification8                   `xml:"CshAcctOwnr"`
	CshAcctSvcr *BranchAndFinancialInstitutionIdentification6 `xml:"CshAcctSvcr"`
	PrcgSts     *ProcessingStatus71Choice                     `xml:"PrcgSts"`
	Mod         []*IntraBalanceModification6                  `xml:"Mod"`
}

// IntraBalanceModification6 ...
type IntraBalanceModification6 struct {
	CshAcct         *CashAccount38                                `xml:"CshAcct"`
	CshAcctOwnr     *SystemPartyIdentification8                   `xml:"CshAcctOwnr"`
	CshAcctSvcr     *BranchAndFinancialInstitutionIdentification6 `xml:"CshAcctSvcr"`
	PrcgSts         *ProcessingStatus71Choice                     `xml:"PrcgSts"`
	ReqRef          string                                        `xml:"ReqRef"`
	StsDt           string                                        `xml:"StsDt"`
	ReqDtls         *RequestDetails22                             `xml:"ReqDtls"`
	UndrlygIntraBal *IntraBalance5                                `xml:"UndrlygIntraBal"`
}

// IntraBalanceMovementModificationReportV01 ...
type IntraBalanceMovementModificationReportV01 struct {
	Id          *DocumentIdentification51              `xml:"Id"`
	Pgntn       *Pagination1                           `xml:"Pgntn"`
	RptGnlDtls  *IntraBalanceReport5                   `xml:"RptGnlDtls"`
	RptOrErr    *IntraBalanceOrOperationalError8Choice `xml:"RptOrErr"`
	SplmtryData []*SupplementaryData1                  `xml:"SplmtryData"`
}

// IntraBalanceOrOperationalError8Choice ...
type IntraBalanceOrOperationalError8Choice struct {
	Mods    []*IntraBalanceModification5 `xml:"Mods"`
	OprlErr []*ErrorHandling5            `xml:"OprlErr"`
}

// IntraBalanceReport5 ...
type IntraBalanceReport5 struct {
	RptNb     *Number3Choice          `xml:"RptNb"`
	QryRef    string                  `xml:"QryRef"`
	RptId     string                  `xml:"RptId"`
	RptDtTm   *DateAndDateTime2Choice `xml:"RptDtTm"`
	RptPrd    *Period7Choice          `xml:"RptPrd"`
	QryTp     string                  `xml:"QryTp"`
	Frqcy     *Frequency22Choice      `xml:"Frqcy"`
	UpdTp     *UpdateType15Choice     `xml:"UpdTp"`
	ActvtyInd bool                    `xml:"ActvtyInd"`
}

// LEIIdentifier ...
type LEIIdentifier string

// LinkageType1Code ...
type LinkageType1Code string

// LinkageType3Choice ...
type LinkageType3Choice struct {
	Cd    string                   `xml:"Cd"`
	Prtry *GenericIdentification30 `xml:"Prtry"`
}

// Linkages57 ...
type Linkages57 struct {
	PrcgPos *ProcessingPosition7Choice    `xml:"PrcgPos"`
	MsgNb   *DocumentNumber5Choice        `xml:"MsgNb"`
	Ref     *References34Choice           `xml:"Ref"`
	RefOwnr *PartyIdentification127Choice `xml:"RefOwnr"`
}

// Max140Text ...
type Max140Text string

// Max16Text ...
type Max16Text string

// Max2048Text ...
type Max2048Text string

// Max210Text ...
type Max210Text string

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

// MovementResponseType1Code ...
type MovementResponseType1Code string

// NameAndAddress5 ...
type NameAndAddress5 struct {
	Nm  string          `xml:"Nm"`
	Adr *PostalAddress1 `xml:"Adr"`
}

// NoReasonCode ...
type NoReasonCode string

// Number3Choice ...
type Number3Choice struct {
	Shrt string `xml:"Shrt"`
	Lng  string `xml:"Lng"`
}

// Pagination1 ...
type Pagination1 struct {
	PgNb      string `xml:"PgNb"`
	LastPgInd bool   `xml:"LastPgInd"`
}

// PartyIdentification120Choice ...
type PartyIdentification120Choice struct {
	AnyBIC   string                   `xml:"AnyBIC"`
	PrtryId  *GenericIdentification36 `xml:"PrtryId"`
	NmAndAdr *NameAndAddress5         `xml:"NmAndAdr"`
}

// PartyIdentification127Choice ...
type PartyIdentification127Choice struct {
	AnyBIC  string                   `xml:"AnyBIC"`
	PrtryId *GenericIdentification36 `xml:"PrtryId"`
}

// PartyIdentification136 ...
type PartyIdentification136 struct {
	Id  *PartyIdentification120Choice `xml:"Id"`
	LEI string                        `xml:"LEI"`
}

// PendingReason16 ...
type PendingReason16 struct {
	Cd          *PendingReason28Choice `xml:"Cd"`
	AddtlRsnInf string                 `xml:"AddtlRsnInf"`
}

// PendingReason28Choice ...
type PendingReason28Choice struct {
	Cd    string                   `xml:"Cd"`
	Prtry *GenericIdentification30 `xml:"Prtry"`
}

// PendingReason6Code ...
type PendingReason6Code string

// PendingStatus38Choice ...
type PendingStatus38Choice struct {
	NoSpcfdRsn string             `xml:"NoSpcfdRsn"`
	Rsn        []*PendingReason16 `xml:"Rsn"`
}

// Period2 ...
type Period2 struct {
	FrDt string `xml:"FrDt"`
	ToDt string `xml:"ToDt"`
}

// Period7Choice ...
type Period7Choice struct {
	FrDtTmToDtTm *DateTimePeriod1 `xml:"FrDtTmToDtTm"`
	FrDtToDt     *Period2         `xml:"FrDtToDt"`
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

// PriorityNumeric4Choice ...
type PriorityNumeric4Choice struct {
	Nmrc  string                   `xml:"Nmrc"`
	Prtry *GenericIdentification30 `xml:"Prtry"`
}

// ProcessingPosition3Code ...
type ProcessingPosition3Code string

// ProcessingPosition7Choice ...
type ProcessingPosition7Choice struct {
	Cd    string                   `xml:"Cd"`
	Prtry *GenericIdentification30 `xml:"Prtry"`
}

// ProcessingStatus71Choice ...
type ProcessingStatus71Choice struct {
	AckdAccptd *AcknowledgedAcceptedStatus21Choice `xml:"AckdAccptd"`
	Pdg        *PendingStatus38Choice              `xml:"Pdg"`
	Rjctd      *RejectionOrRepairStatus40Choice    `xml:"Rjctd"`
	Rpr        *RejectionOrRepairStatus39Choice    `xml:"Rpr"`
	Dnd        *DeniedStatus16Choice               `xml:"Dnd"`
	Cmpltd     *ProprietaryReason4                 `xml:"Cmpltd"`
	Prtry      *ProprietaryStatusAndReason6        `xml:"Prtry"`
}

// ProprietaryReason4 ...
type ProprietaryReason4 struct {
	Rsn         *GenericIdentification30 `xml:"Rsn"`
	AddtlRsnInf string                   `xml:"AddtlRsnInf"`
}

// ProprietaryStatusAndReason6 ...
type ProprietaryStatusAndReason6 struct {
	PrtrySts *GenericIdentification30 `xml:"PrtrySts"`
	PrtryRsn []*ProprietaryReason4    `xml:"PrtryRsn"`
}

// ProxyAccountIdentification1 ...
type ProxyAccountIdentification1 struct {
	Tp *ProxyAccountType1Choice `xml:"Tp"`
	Id string                   `xml:"Id"`
}

// ProxyAccountType1Choice ...
type ProxyAccountType1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// References14 ...
type References14 struct {
	AcctOwnrTxId      string `xml:"AcctOwnrTxId"`
	AcctSvcrTxId      string `xml:"AcctSvcrTxId"`
	MktInfrstrctrTxId string `xml:"MktInfrstrctrTxId"`
	PrcrTxId          string `xml:"PrcrTxId"`
	PoolId            string `xml:"PoolId"`
}

// References34Choice ...
type References34Choice struct {
	SctiesSttlmTxId   string `xml:"SctiesSttlmTxId"`
	IntraPosMvmntId   string `xml:"IntraPosMvmntId"`
	IntraBalMvmntId   string `xml:"IntraBalMvmntId"`
	AcctSvcrTxId      string `xml:"AcctSvcrTxId"`
	MktInfrstrctrTxId string `xml:"MktInfrstrctrTxId"`
	PoolId            string `xml:"PoolId"`
	OthrTxId          string `xml:"OthrTxId"`
}

// RejectionAndRepairReason33Choice ...
type RejectionAndRepairReason33Choice struct {
	Cd    string                   `xml:"Cd"`
	Prtry *GenericIdentification30 `xml:"Prtry"`
}

// RejectionAndRepairReason34Choice ...
type RejectionAndRepairReason34Choice struct {
	Cd    string                   `xml:"Cd"`
	Prtry *GenericIdentification30 `xml:"Prtry"`
}

// RejectionOrRepairReason33 ...
type RejectionOrRepairReason33 struct {
	Cd          *RejectionAndRepairReason33Choice `xml:"Cd"`
	AddtlRsnInf string                            `xml:"AddtlRsnInf"`
}

// RejectionOrRepairReason34 ...
type RejectionOrRepairReason34 struct {
	Cd          *RejectionAndRepairReason34Choice `xml:"Cd"`
	AddtlRsnInf string                            `xml:"AddtlRsnInf"`
}

// RejectionOrRepairStatus39Choice ...
type RejectionOrRepairStatus39Choice struct {
	NoSpcfdRsn string                       `xml:"NoSpcfdRsn"`
	Rsn        []*RejectionOrRepairReason33 `xml:"Rsn"`
}

// RejectionOrRepairStatus40Choice ...
type RejectionOrRepairStatus40Choice struct {
	NoSpcfdRsn string                       `xml:"NoSpcfdRsn"`
	Rsn        []*RejectionOrRepairReason34 `xml:"Rsn"`
}

// RejectionReason34Code ...
type RejectionReason34Code string

// RejectionReason35Code ...
type RejectionReason35Code string

// RequestDetails22 ...
type RequestDetails22 struct {
	Ref          *References14              `xml:"Ref"`
	Lkg          *LinkageType3Choice        `xml:"Lkg"`
	Prty         *PriorityNumeric4Choice    `xml:"Prty"`
	OthrPrcg     []*GenericIdentification30 `xml:"OthrPrcg"`
	PrtlSttlmInd bool                       `xml:"PrtlSttlmInd"`
	ClrChanl     string                     `xml:"ClrChanl"`
	Lnkgs        []*Linkages57              `xml:"Lnkgs"`
}

// StatementUpdateType1Code ...
type StatementUpdateType1Code string

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

// UpdateType15Choice ...
type UpdateType15Choice struct {
	Cd    string                   `xml:"Cd"`
	Prtry *GenericIdentification30 `xml:"Prtry"`
}

// YesNoIndicator ...
type YesNoIndicator bool
