package schema

import (
	"encoding/xml"
)

// Document ...
type Document *Document

// AccountIdentification3Choice ...
type AccountIdentification3Choice struct {
	IBAN      string                            `xml:"IBAN"`
	BBAN      string                            `xml:"BBAN"`
	UPIC      string                            `xml:"UPIC"`
	PrtryAcct *SimpleIdentificationInformation2 `xml:"PrtryAcct"`
}

// AddressType2Code ...
type AddressType2Code string

// AmendmentInformationDetails1 ...
type AmendmentInformationDetails1 struct {
	OrgnlMndtId      string                                        `xml:"OrgnlMndtId"`
	OrgnlCdtrSchmeId *PartyIdentification8                         `xml:"OrgnlCdtrSchmeId"`
	OrgnlCdtrAgt     *BranchAndFinancialInstitutionIdentification3 `xml:"OrgnlCdtrAgt"`
	OrgnlCdtrAgtAcct *CashAccount7                                 `xml:"OrgnlCdtrAgtAcct"`
	OrgnlDbtr        *PartyIdentification8                         `xml:"OrgnlDbtr"`
	OrgnlDbtrAcct    *CashAccount7                                 `xml:"OrgnlDbtrAcct"`
	OrgnlDbtrAgt     *BranchAndFinancialInstitutionIdentification3 `xml:"OrgnlDbtrAgt"`
	OrgnlDbtrAgtAcct *CashAccount7                                 `xml:"OrgnlDbtrAgtAcct"`
	OrgnlFnlColltnDt string                                        `xml:"OrgnlFnlColltnDt"`
	OrgnlFrqcy       string                                        `xml:"OrgnlFrqcy"`
}

// AmountType2Choice ...
type AmountType2Choice struct {
	InstdAmt *CurrencyAndAmount `xml:"InstdAmt"`
	EqvtAmt  *EquivalentAmount  `xml:"EqvtAmt"`
}

// BBANIdentifier ...
type BBANIdentifier string

// BEIIdentifier ...
type BEIIdentifier string

// BICIdentifier ...
type BICIdentifier string

// BranchAndFinancialInstitutionIdentification3 ...
type BranchAndFinancialInstitutionIdentification3 struct {
	FinInstnId *FinancialInstitutionIdentification5Choice `xml:"FinInstnId"`
	BrnchId    *BranchData                                `xml:"BrnchId"`
}

// BranchData ...
type BranchData struct {
	Id      string          `xml:"Id"`
	Nm      string          `xml:"Nm"`
	PstlAdr *PostalAddress1 `xml:"PstlAdr"`
}

// CHIPSUniversalIdentifier ...
type CHIPSUniversalIdentifier string

// CancellationReason1Choice ...
type CancellationReason1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// CancellationReason2Code ...
type CancellationReason2Code string

// CancellationReasonInformation1 ...
type CancellationReasonInformation1 struct {
	CxlOrgtr       *PartyIdentification8      `xml:"CxlOrgtr"`
	CxlRsn         *CancellationReason1Choice `xml:"CxlRsn"`
	AddtlCxlRsnInf []string                   `xml:"AddtlCxlRsnInf"`
}

// CashAccount7 ...
type CashAccount7 struct {
	Id  *AccountIdentification3Choice `xml:"Id"`
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

// CashClearingSystem3Code ...
type CashClearingSystem3Code string

// ClearingChannel2Code ...
type ClearingChannel2Code string

// ClearingSystemIdentification1Choice ...
type ClearingSystemIdentification1Choice struct {
	ClrSysId string `xml:"ClrSysId"`
	Prtry    string `xml:"Prtry"`
}

// ClearingSystemMemberIdentification3Choice ...
type ClearingSystemMemberIdentification3Choice struct {
	Id    string `xml:"Id"`
	Prtry string `xml:"Prtry"`
}

// CountryCode ...
type CountryCode string

// CreditorReferenceInformation1 ...
type CreditorReferenceInformation1 struct {
	CdtrRefTp *CreditorReferenceType1 `xml:"CdtrRefTp"`
	CdtrRef   string                  `xml:"CdtrRef"`
}

// CreditorReferenceType1 ...
type CreditorReferenceType1 struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
	Issr  string `xml:"Issr"`
}

// CurrencyAndAmountSimpleType ...
type CurrencyAndAmountSimpleType float64

// CurrencyAndAmount ...
type CurrencyAndAmount struct {
	CcyAttr string  `xml:"Ccy,attr"`
	Value   float64 `xml:",chardata"`
}

// CurrencyCode ...
type CurrencyCode string

// DateAndPlaceOfBirth ...
type DateAndPlaceOfBirth struct {
	BirthDt     string `xml:"BirthDt"`
	PrvcOfBirth string `xml:"PrvcOfBirth"`
	CityOfBirth string `xml:"CityOfBirth"`
	CtryOfBirth string `xml:"CtryOfBirth"`
}

// DecimalNumber ...
type DecimalNumber float64

// DocumentType2Code ...
type DocumentType2Code string

// DocumentType3Code ...
type DocumentType3Code string

// DunsIdentifier ...
type DunsIdentifier string

// EANGLNIdentifier ...
type EANGLNIdentifier string

// EquivalentAmount ...
type EquivalentAmount struct {
	Amt      *CurrencyAndAmount `xml:"Amt"`
	CcyOfTrf string             `xml:"CcyOfTrf"`
}

// ExternalClearingSystemMemberCode ...
type ExternalClearingSystemMemberCode string

// ExternalLocalInstrumentCode ...
type ExternalLocalInstrumentCode string

// FinancialInstitutionIdentification3 ...
type FinancialInstitutionIdentification3 struct {
	BIC         string                                     `xml:"BIC"`
	ClrSysMmbId *ClearingSystemMemberIdentification3Choice `xml:"ClrSysMmbId"`
	Nm          string                                     `xml:"Nm"`
	PstlAdr     *PostalAddress1                            `xml:"PstlAdr"`
	PrtryId     *GenericIdentification3                    `xml:"PrtryId"`
}

// FinancialInstitutionIdentification5Choice ...
type FinancialInstitutionIdentification5Choice struct {
	BIC         string                                     `xml:"BIC"`
	ClrSysMmbId *ClearingSystemMemberIdentification3Choice `xml:"ClrSysMmbId"`
	NmAndAdr    *NameAndAddress7                           `xml:"NmAndAdr"`
	PrtryId     *GenericIdentification3                    `xml:"PrtryId"`
	CmbndId     *FinancialInstitutionIdentification3       `xml:"CmbndId"`
}

// Frequency1Code ...
type Frequency1Code string

// GenericIdentification3 ...
type GenericIdentification3 struct {
	Id   string `xml:"Id"`
	Issr string `xml:"Issr"`
}

// GenericIdentification4 ...
type GenericIdentification4 struct {
	Id   string `xml:"Id"`
	IdTp string `xml:"IdTp"`
}

// GroupHeader7 ...
type GroupHeader7 struct {
	MsgId    string                                        `xml:"MsgId"`
	CreDtTm  string                                        `xml:"CreDtTm"`
	NbOfTxs  string                                        `xml:"NbOfTxs"`
	CtrlSum  float64                                       `xml:"CtrlSum"`
	GrpCxl   bool                                          `xml:"GrpCxl"`
	InitgPty *PartyIdentification8                         `xml:"InitgPty"`
	FwdgAgt  *BranchAndFinancialInstitutionIdentification3 `xml:"FwdgAgt"`
	DbtrAgt  *BranchAndFinancialInstitutionIdentification3 `xml:"DbtrAgt"`
	CdtrAgt  *BranchAndFinancialInstitutionIdentification3 `xml:"CdtrAgt"`
	InstgAgt *BranchAndFinancialInstitutionIdentification3 `xml:"InstgAgt"`
	InstdAgt *BranchAndFinancialInstitutionIdentification3 `xml:"InstdAgt"`
}

// GroupingIndicator ...
type GroupingIndicator bool

// IBANIdentifier ...
type IBANIdentifier string

// IBEIIdentifier ...
type IBEIIdentifier string

// ISODate ...
type ISODate string

// ISODateTime ...
type ISODateTime string

// LocalInstrument1Choice ...
type LocalInstrument1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// MandateRelatedInformation1 ...
type MandateRelatedInformation1 struct {
	MndtId        string                        `xml:"MndtId"`
	DtOfSgntr     string                        `xml:"DtOfSgntr"`
	AmdmntInd     bool                          `xml:"AmdmntInd"`
	AmdmntInfDtls *AmendmentInformationDetails1 `xml:"AmdmntInfDtls"`
	ElctrncSgntr  string                        `xml:"ElctrncSgntr"`
	FrstColltnDt  string                        `xml:"FrstColltnDt"`
	FnlColltnDt   string                        `xml:"FnlColltnDt"`
	Frqcy         string                        `xml:"Frqcy"`
}

// Max1025Text ...
type Max1025Text string

// Max105Text ...
type Max105Text string

// Max140Text ...
type Max140Text string

// Max15NumericText ...
type Max15NumericText string

// Max16Text ...
type Max16Text string

// Max34Text ...
type Max34Text string

// Max35Text ...
type Max35Text string

// Max70Text ...
type Max70Text string

// NameAndAddress7 ...
type NameAndAddress7 struct {
	Nm      string          `xml:"Nm"`
	PstlAdr *PostalAddress1 `xml:"PstlAdr"`
}

// OrganisationIdentification2 ...
type OrganisationIdentification2 struct {
	BIC     string                  `xml:"BIC"`
	IBEI    string                  `xml:"IBEI"`
	BEI     string                  `xml:"BEI"`
	EANGLN  string                  `xml:"EANGLN"`
	USCHU   string                  `xml:"USCHU"`
	DUNS    string                  `xml:"DUNS"`
	BkPtyId string                  `xml:"BkPtyId"`
	TaxIdNb string                  `xml:"TaxIdNb"`
	PrtryId *GenericIdentification3 `xml:"PrtryId"`
}

// OriginalGroupInformation4 ...
type OriginalGroupInformation4 struct {
	OrgnlMsgId   string                            `xml:"OrgnlMsgId"`
	OrgnlMsgNmId string                            `xml:"OrgnlMsgNmId"`
	OrgnlCreDtTm string                            `xml:"OrgnlCreDtTm"`
	CxlRsnInf    []*CancellationReasonInformation1 `xml:"CxlRsnInf"`
}

// OriginalTransactionReference1 ...
type OriginalTransactionReference1 struct {
	IntrBkSttlmAmt *CurrencyAndAmount                            `xml:"IntrBkSttlmAmt"`
	Amt            *AmountType2Choice                            `xml:"Amt"`
	IntrBkSttlmDt  string                                        `xml:"IntrBkSttlmDt"`
	ReqdExctnDt    string                                        `xml:"ReqdExctnDt"`
	ReqdColltnDt   string                                        `xml:"ReqdColltnDt"`
	CdtrSchmeId    *PartyIdentification8                         `xml:"CdtrSchmeId"`
	SttlmInf       *SettlementInformation3                       `xml:"SttlmInf"`
	PmtTpInf       *PaymentTypeInformation6                      `xml:"PmtTpInf"`
	PmtMtd         string                                        `xml:"PmtMtd"`
	MndtRltdInf    *MandateRelatedInformation1                   `xml:"MndtRltdInf"`
	RmtInf         *RemittanceInformation1                       `xml:"RmtInf"`
	UltmtDbtr      *PartyIdentification8                         `xml:"UltmtDbtr"`
	Dbtr           *PartyIdentification8                         `xml:"Dbtr"`
	DbtrAcct       *CashAccount7                                 `xml:"DbtrAcct"`
	DbtrAgt        *BranchAndFinancialInstitutionIdentification3 `xml:"DbtrAgt"`
	DbtrAgtAcct    *CashAccount7                                 `xml:"DbtrAgtAcct"`
	CdtrAgt        *BranchAndFinancialInstitutionIdentification3 `xml:"CdtrAgt"`
	CdtrAgtAcct    *CashAccount7                                 `xml:"CdtrAgtAcct"`
	Cdtr           *PartyIdentification8                         `xml:"Cdtr"`
	CdtrAcct       *CashAccount7                                 `xml:"CdtrAcct"`
	UltmtCdtr      *PartyIdentification8                         `xml:"UltmtCdtr"`
}

// Party2Choice ...
type Party2Choice struct {
	OrgId  *OrganisationIdentification2 `xml:"OrgId"`
	PrvtId []*PersonIdentification3     `xml:"PrvtId"`
}

// PartyIdentification8 ...
type PartyIdentification8 struct {
	Nm        string          `xml:"Nm"`
	PstlAdr   *PostalAddress1 `xml:"PstlAdr"`
	Id        *Party2Choice   `xml:"Id"`
	CtryOfRes string          `xml:"CtryOfRes"`
}

// PaymentCategoryPurpose1Code ...
type PaymentCategoryPurpose1Code string

// PaymentMethod4Code ...
type PaymentMethod4Code string

// PaymentTransactionInformation3 ...
type PaymentTransactionInformation3 struct {
	CxlId               string                                        `xml:"CxlId"`
	OrgnlPmtInfId       string                                        `xml:"OrgnlPmtInfId"`
	OrgnlInstrId        string                                        `xml:"OrgnlInstrId"`
	OrgnlEndToEndId     string                                        `xml:"OrgnlEndToEndId"`
	OrgnlTxId           string                                        `xml:"OrgnlTxId"`
	OrgnlIntrBkSttlmAmt *CurrencyAndAmount                            `xml:"OrgnlIntrBkSttlmAmt"`
	OrgnlInstdAmt       *CurrencyAndAmount                            `xml:"OrgnlInstdAmt"`
	InstgAgt            *BranchAndFinancialInstitutionIdentification3 `xml:"InstgAgt"`
	InstdAgt            *BranchAndFinancialInstitutionIdentification3 `xml:"InstdAgt"`
	CxlRsnInf           []*CancellationReasonInformation1             `xml:"CxlRsnInf"`
	OrgnlTxRef          *OriginalTransactionReference1                `xml:"OrgnlTxRef"`
}

// PaymentTypeInformation6 ...
type PaymentTypeInformation6 struct {
	InstrPrty string                  `xml:"InstrPrty"`
	SvcLvl    *ServiceLevel2Choice    `xml:"SvcLvl"`
	ClrChanl  string                  `xml:"ClrChanl"`
	LclInstrm *LocalInstrument1Choice `xml:"LclInstrm"`
	SeqTp     string                  `xml:"SeqTp"`
	CtgyPurp  string                  `xml:"CtgyPurp"`
}

// PersonIdentification3 ...
type PersonIdentification3 struct {
	DrvrsLicNb      string                  `xml:"DrvrsLicNb"`
	CstmrNb         string                  `xml:"CstmrNb"`
	SclSctyNb       string                  `xml:"SclSctyNb"`
	AlnRegnNb       string                  `xml:"AlnRegnNb"`
	PsptNb          string                  `xml:"PsptNb"`
	TaxIdNb         string                  `xml:"TaxIdNb"`
	IdntyCardNb     string                  `xml:"IdntyCardNb"`
	MplyrIdNb       string                  `xml:"MplyrIdNb"`
	DtAndPlcOfBirth *DateAndPlaceOfBirth    `xml:"DtAndPlcOfBirth"`
	OthrId          *GenericIdentification4 `xml:"OthrId"`
	Issr            string                  `xml:"Issr"`
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

// Priority2Code ...
type Priority2Code string

// ReferredDocumentAmount1Choice ...
type ReferredDocumentAmount1Choice struct {
	DuePyblAmt   *CurrencyAndAmount `xml:"DuePyblAmt"`
	DscntApldAmt *CurrencyAndAmount `xml:"DscntApldAmt"`
	RmtdAmt      *CurrencyAndAmount `xml:"RmtdAmt"`
	CdtNoteAmt   *CurrencyAndAmount `xml:"CdtNoteAmt"`
	TaxAmt       *CurrencyAndAmount `xml:"TaxAmt"`
}

// ReferredDocumentInformation1 ...
type ReferredDocumentInformation1 struct {
	RfrdDocTp *ReferredDocumentType1 `xml:"RfrdDocTp"`
	RfrdDocNb string                 `xml:"RfrdDocNb"`
}

// ReferredDocumentType1 ...
type ReferredDocumentType1 struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
	Issr  string `xml:"Issr"`
}

// RemittanceInformation1 ...
type RemittanceInformation1 struct {
	Ustrd []string                            `xml:"Ustrd"`
	Strd  []*StructuredRemittanceInformation6 `xml:"Strd"`
}

// SequenceType1Code ...
type SequenceType1Code string

// ServiceLevel1Code ...
type ServiceLevel1Code string

// ServiceLevel2Choice ...
type ServiceLevel2Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// SettlementInformation3 ...
type SettlementInformation3 struct {
	SttlmMtd             string                                        `xml:"SttlmMtd"`
	SttlmAcct            *CashAccount7                                 `xml:"SttlmAcct"`
	ClrSys               *ClearingSystemIdentification1Choice          `xml:"ClrSys"`
	InstgRmbrsmntAgt     *BranchAndFinancialInstitutionIdentification3 `xml:"InstgRmbrsmntAgt"`
	InstgRmbrsmntAgtAcct *CashAccount7                                 `xml:"InstgRmbrsmntAgtAcct"`
	InstdRmbrsmntAgt     *BranchAndFinancialInstitutionIdentification3 `xml:"InstdRmbrsmntAgt"`
	InstdRmbrsmntAgtAcct *CashAccount7                                 `xml:"InstdRmbrsmntAgtAcct"`
	ThrdRmbrsmntAgt      *BranchAndFinancialInstitutionIdentification3 `xml:"ThrdRmbrsmntAgt"`
	ThrdRmbrsmntAgtAcct  *CashAccount7                                 `xml:"ThrdRmbrsmntAgtAcct"`
}

// SettlementMethod1Code ...
type SettlementMethod1Code string

// SimpleIdentificationInformation2 ...
type SimpleIdentificationInformation2 struct {
	Id string `xml:"Id"`
}

// StructuredRemittanceInformation6 ...
type StructuredRemittanceInformation6 struct {
	RfrdDocInf    *ReferredDocumentInformation1    `xml:"RfrdDocInf"`
	RfrdDocRltdDt string                           `xml:"RfrdDocRltdDt"`
	RfrdDocAmt    []*ReferredDocumentAmount1Choice `xml:"RfrdDocAmt"`
	CdtrRefInf    *CreditorReferenceInformation1   `xml:"CdtrRefInf"`
	Invcr         *PartyIdentification8            `xml:"Invcr"`
	Invcee        *PartyIdentification8            `xml:"Invcee"`
	AddtlRmtInf   string                           `xml:"AddtlRmtInf"`
}

// TrueFalseIndicator ...
type TrueFalseIndicator bool

// UPICIdentifier ...
type UPICIdentifier string

// Pain00600101 ...
type Pain00600101 struct {
	XMLName     xml.Name                          `xml:"pain.006.001.01"`
	GrpHdr      *GroupHeader7                     `xml:"GrpHdr"`
	OrgnlGrpInf *OriginalGroupInformation4        `xml:"OrgnlGrpInf"`
	TxInf       []*PaymentTransactionInformation3 `xml:"TxInf"`
}
