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

// AcknowledgedAcceptedStatus24Choice ...
type AcknowledgedAcceptedStatus24Choice struct {
	NoSpcfdRsn string                     `xml:"NoSpcfdRsn"`
	Rsn        []*AcknowledgementReason12 `xml:"Rsn"`
}

// AcknowledgementReason12 ...
type AcknowledgementReason12 struct {
	Cd          *AcknowledgementReason15Choice `xml:"Cd"`
	AddtlRsnInf string                         `xml:"AddtlRsnInf"`
}

// AcknowledgementReason15Choice ...
type AcknowledgementReason15Choice struct {
	Cd    string                   `xml:"Cd"`
	Prtry *GenericIdentification30 `xml:"Prtry"`
}

// AcknowledgementReason3Code ...
type AcknowledgementReason3Code string

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

// CancellationReason10 ...
type CancellationReason10 struct {
	Cd          *CancellationReason21Choice `xml:"Cd"`
	AddtlRsnInf string                      `xml:"AddtlRsnInf"`
}

// CancellationReason21Choice ...
type CancellationReason21Choice struct {
	Cd    string                   `xml:"Cd"`
	Prtry *GenericIdentification30 `xml:"Prtry"`
}

// CancellationStatus15Choice ...
type CancellationStatus15Choice struct {
	NoSpcfdRsn string                  `xml:"NoSpcfdRsn"`
	Rsn        []*CancellationReason10 `xml:"Rsn"`
}

// CancelledStatusReason5Code ...
type CancelledStatusReason5Code string

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

// Exact4AlphaNumericText ...
type Exact4AlphaNumericText string

// Exact4NumericText ...
type Exact4NumericText string

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

// ISODate ...
type ISODate string

// ISODateTime ...
type ISODateTime string

// Identification14 ...
type Identification14 struct {
	Id string `xml:"Id"`
}

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

// IntraBalanceMovementCancellationRequestStatusAdviceV01 ...
type IntraBalanceMovementCancellationRequestStatusAdviceV01 struct {
	Id              *DocumentIdentification51                     `xml:"Id"`
	ReqRef          *Identification14                             `xml:"ReqRef"`
	TxId            *References14                                 `xml:"TxId"`
	PrcgSts         *ProcessingStatus69Choice                     `xml:"PrcgSts"`
	CshAcct         *CashAccount38                                `xml:"CshAcct"`
	CshAcctOwnr     *SystemPartyIdentification8                   `xml:"CshAcctOwnr"`
	CshAcctSvcr     *BranchAndFinancialInstitutionIdentification6 `xml:"CshAcctSvcr"`
	UndrlygIntraBal *IntraBalance5                                `xml:"UndrlygIntraBal"`
	SplmtryData     []*SupplementaryData1                         `xml:"SplmtryData"`
}

// LEIIdentifier ...
type LEIIdentifier string

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

// Max70Text ...
type Max70Text string

// NameAndAddress5 ...
type NameAndAddress5 struct {
	Nm  string          `xml:"Nm"`
	Adr *PostalAddress1 `xml:"Adr"`
}

// NoReasonCode ...
type NoReasonCode string

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

// PendingReason17 ...
type PendingReason17 struct {
	Cd          *PendingReason30Choice `xml:"Cd"`
	AddtlRsnInf string                 `xml:"AddtlRsnInf"`
}

// PendingReason30Choice ...
type PendingReason30Choice struct {
	Cd    string                   `xml:"Cd"`
	Prtry *GenericIdentification30 `xml:"Prtry"`
}

// PendingReason9Code ...
type PendingReason9Code string

// PendingStatus39Choice ...
type PendingStatus39Choice struct {
	NoSpcfdRsn string             `xml:"NoSpcfdRsn"`
	Rsn        []*PendingReason17 `xml:"Rsn"`
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

// ProcessingStatus69Choice ...
type ProcessingStatus69Choice struct {
	PdgCxl     *PendingStatus39Choice              `xml:"PdgCxl"`
	Rjctd      *RejectionOrRepairStatus39Choice    `xml:"Rjctd"`
	Rpr        *RejectionOrRepairStatus39Choice    `xml:"Rpr"`
	AckdAccptd *AcknowledgedAcceptedStatus24Choice `xml:"AckdAccptd"`
	Prtry      *ProprietaryStatusAndReason6        `xml:"Prtry"`
	Dnd        *DeniedStatus16Choice               `xml:"Dnd"`
	Canc       *CancellationStatus15Choice         `xml:"Canc"`
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

// RejectionAndRepairReason33Choice ...
type RejectionAndRepairReason33Choice struct {
	Cd    string                   `xml:"Cd"`
	Prtry *GenericIdentification30 `xml:"Prtry"`
}

// RejectionOrRepairReason33 ...
type RejectionOrRepairReason33 struct {
	Cd          *RejectionAndRepairReason33Choice `xml:"Cd"`
	AddtlRsnInf string                            `xml:"AddtlRsnInf"`
}

// RejectionOrRepairStatus39Choice ...
type RejectionOrRepairStatus39Choice struct {
	NoSpcfdRsn string                       `xml:"NoSpcfdRsn"`
	Rsn        []*RejectionOrRepairReason33 `xml:"Rsn"`
}

// RejectionReason34Code ...
type RejectionReason34Code string

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
