package schema

// Document ...
type Document *Document

// AccountIdentification4Choice ...
type AccountIdentification4Choice struct {
	IBAN string                         `xml:"IBAN"`
	Othr *GenericAccountIdentification1 `xml:"Othr"`
}

// AccountLevel1Code ...
type AccountLevel1Code string

// AccountLevel2Code ...
type AccountLevel2Code string

// AccountSchemeName1Choice ...
type AccountSchemeName1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// AccountTax1 ...
type AccountTax1 struct {
	ClctnMtd   string                    `xml:"ClctnMtd"`
	Rgn        string                    `xml:"Rgn"`
	NonResCtry *ResidenceLocation1Choice `xml:"NonResCtry"`
}

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

// AmountAndDirection34 ...
type AmountAndDirection34 struct {
	Amt *ActiveOrHistoricCurrencyAndAmount `xml:"Amt"`
	Sgn bool                               `xml:"Sgn"`
}

// AnyBICIdentifier ...
type AnyBICIdentifier string

// BICFIIdentifier ...
type BICFIIdentifier string

// BalanceAdjustment1 ...
type BalanceAdjustment1 struct {
	Tp                string                `xml:"Tp"`
	Desc              string                `xml:"Desc"`
	BalAmt            *AmountAndDirection34 `xml:"BalAmt"`
	AvrgAmt           *AmountAndDirection34 `xml:"AvrgAmt"`
	ErrDt             string                `xml:"ErrDt"`
	PstngDt           string                `xml:"PstngDt"`
	Days              float64               `xml:"Days"`
	EarngsAdjstmntAmt *AmountAndDirection34 `xml:"EarngsAdjstmntAmt"`
}

// BalanceAdjustmentType1Code ...
type BalanceAdjustmentType1Code string

// BankServicesBillingStatementV01 ...
type BankServicesBillingStatementV01 struct {
	RptHdr      *ReportHeader3     `xml:"RptHdr"`
	BllgStmtGrp []*StatementGroup1 `xml:"BllgStmtGrp"`
}

// BaseOneRate ...
type BaseOneRate float64

// BillingBalance1 ...
type BillingBalance1 struct {
	Tp    *BillingBalanceType1Choice `xml:"Tp"`
	Val   *AmountAndDirection34      `xml:"Val"`
	CcyTp string                     `xml:"CcyTp"`
}

// BillingBalanceType1Choice ...
type BillingBalanceType1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// BillingChargeMethod1Code ...
type BillingChargeMethod1Code string

// BillingCompensation1 ...
type BillingCompensation1 struct {
	Tp    *BillingCompensationType1Choice `xml:"Tp"`
	Val   *AmountAndDirection34           `xml:"Val"`
	CcyTp string                          `xml:"CcyTp"`
}

// BillingCompensationType1Choice ...
type BillingCompensationType1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// BillingCurrencyType1Code ...
type BillingCurrencyType1Code string

// BillingCurrencyType2Code ...
type BillingCurrencyType2Code string

// BillingMethod1 ...
type BillingMethod1 struct {
	SvcChrgHstAmt *AmountAndDirection34   `xml:"SvcChrgHstAmt"`
	SvcTax        *BillingServicesAmount1 `xml:"SvcTax"`
	TtlChrg       *BillingServicesAmount2 `xml:"TtlChrg"`
	TaxId         []*BillingServicesTax1  `xml:"TaxId"`
}

// BillingMethod1Choice ...
type BillingMethod1Choice struct {
	MtdA *BillingMethod1 `xml:"MtdA"`
	MtdB *BillingMethod2 `xml:"MtdB"`
	MtdD *BillingMethod3 `xml:"MtdD"`
}

// BillingMethod2 ...
type BillingMethod2 struct {
	SvcChrgHstAmt *AmountAndDirection34   `xml:"SvcChrgHstAmt"`
	SvcTax        *BillingServicesAmount1 `xml:"SvcTax"`
	TaxId         []*BillingServicesTax1  `xml:"TaxId"`
}

// BillingMethod3 ...
type BillingMethod3 struct {
	SvcTaxPricAmt *AmountAndDirection34  `xml:"SvcTaxPricAmt"`
	TaxId         []*BillingServicesTax2 `xml:"TaxId"`
}

// BillingMethod4 ...
type BillingMethod4 struct {
	SvcDtl   []*BillingServiceParameters2 `xml:"SvcDtl"`
	TaxClctn *TaxCalculation1             `xml:"TaxClctn"`
}

// BillingPrice1 ...
type BillingPrice1 struct {
	Ccy      string                `xml:"Ccy"`
	UnitPric *AmountAndDirection34 `xml:"UnitPric"`
	Mtd      string                `xml:"Mtd"`
	Rule     string                `xml:"Rule"`
}

// BillingRate1 ...
type BillingRate1 struct {
	Id        *BillingRateIdentification1Choice `xml:"Id"`
	Val       float64                           `xml:"Val"`
	DaysInPrd float64                           `xml:"DaysInPrd"`
	DaysInYr  float64                           `xml:"DaysInYr"`
}

// BillingRateIdentification1Choice ...
type BillingRateIdentification1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// BillingService1 ...
type BillingService1 struct {
	SvcDtl            *BillingServiceParameters1 `xml:"SvcDtl"`
	Pric              *BillingPrice1             `xml:"Pric"`
	PmtMtd            string                     `xml:"PmtMtd"`
	OrgnlChrgPric     *AmountAndDirection34      `xml:"OrgnlChrgPric"`
	OrgnlChrgSttlmAmt *AmountAndDirection34      `xml:"OrgnlChrgSttlmAmt"`
	BalReqrdAcctAmt   *AmountAndDirection34      `xml:"BalReqrdAcctAmt"`
	TaxDsgnt          *ServiceTaxDesignation1    `xml:"TaxDsgnt"`
	TaxClctn          *BillingMethod1Choice      `xml:"TaxClctn"`
}

// BillingServiceAdjustment1 ...
type BillingServiceAdjustment1 struct {
	Tp           string                            `xml:"Tp"`
	Desc         string                            `xml:"Desc"`
	Amt          *AmountAndDirection34             `xml:"Amt"`
	BalReqrdAmt  *AmountAndDirection34             `xml:"BalReqrdAmt"`
	ErrDt        string                            `xml:"ErrDt"`
	AdjstmntId   string                            `xml:"AdjstmntId"`
	SubSvc       *BillingSubServiceIdentification1 `xml:"SubSvc"`
	PricChng     *AmountAndDirection34             `xml:"PricChng"`
	OrgnlPric    *AmountAndDirection34             `xml:"OrgnlPric"`
	NewPric      *AmountAndDirection34             `xml:"NewPric"`
	VolChng      float64                           `xml:"VolChng"`
	OrgnlVol     float64                           `xml:"OrgnlVol"`
	NewVol       float64                           `xml:"NewVol"`
	OrgnlChrgAmt *AmountAndDirection34             `xml:"OrgnlChrgAmt"`
	NewChrgAmt   *AmountAndDirection34             `xml:"NewChrgAmt"`
}

// BillingServiceCommonIdentification1 ...
type BillingServiceCommonIdentification1 struct {
	Issr string `xml:"Issr"`
	Id   string `xml:"Id"`
}

// BillingServiceIdentification1 ...
type BillingServiceIdentification1 struct {
	Id     string                               `xml:"Id"`
	SubSvc *BillingSubServiceIdentification1    `xml:"SubSvc"`
	Desc   string                               `xml:"Desc"`
	CmonCd *BillingServiceCommonIdentification1 `xml:"CmonCd"`
	SvcTp  string                               `xml:"SvcTp"`
}

// BillingServiceIdentification2 ...
type BillingServiceIdentification2 struct {
	Id     string                            `xml:"Id"`
	SubSvc *BillingSubServiceIdentification1 `xml:"SubSvc"`
	Desc   string                            `xml:"Desc"`
}

// BillingServiceParameters1 ...
type BillingServiceParameters1 struct {
	BkSvc *BillingServiceIdentification1 `xml:"BkSvc"`
	Vol   float64                        `xml:"Vol"`
}

// BillingServiceParameters2 ...
type BillingServiceParameters2 struct {
	BkSvc      *BillingServiceIdentification2 `xml:"BkSvc"`
	Vol        float64                        `xml:"Vol"`
	UnitPric   *AmountAndDirection34          `xml:"UnitPric"`
	SvcChrgAmt *AmountAndDirection34          `xml:"SvcChrgAmt"`
}

// BillingServicesAmount1 ...
type BillingServicesAmount1 struct {
	HstAmt   *AmountAndDirection34 `xml:"HstAmt"`
	PricgAmt *AmountAndDirection34 `xml:"PricgAmt"`
}

// BillingServicesAmount2 ...
type BillingServicesAmount2 struct {
	HstAmt   *AmountAndDirection34 `xml:"HstAmt"`
	SttlmAmt *AmountAndDirection34 `xml:"SttlmAmt"`
	PricgAmt *AmountAndDirection34 `xml:"PricgAmt"`
}

// BillingServicesAmount3 ...
type BillingServicesAmount3 struct {
	SrcAmt *AmountAndDirection34 `xml:"SrcAmt"`
	HstAmt *AmountAndDirection34 `xml:"HstAmt"`
}

// BillingServicesTax1 ...
type BillingServicesTax1 struct {
	Nb       string                `xml:"Nb"`
	Desc     string                `xml:"Desc"`
	Rate     float64               `xml:"Rate"`
	HstAmt   *AmountAndDirection34 `xml:"HstAmt"`
	PricgAmt *AmountAndDirection34 `xml:"PricgAmt"`
}

// BillingServicesTax2 ...
type BillingServicesTax2 struct {
	Nb       string                `xml:"Nb"`
	Desc     string                `xml:"Desc"`
	Rate     float64               `xml:"Rate"`
	PricgAmt *AmountAndDirection34 `xml:"PricgAmt"`
}

// BillingServicesTax3 ...
type BillingServicesTax3 struct {
	Nb        string                `xml:"Nb"`
	Desc      string                `xml:"Desc"`
	Rate      float64               `xml:"Rate"`
	TtlTaxAmt *AmountAndDirection34 `xml:"TtlTaxAmt"`
}

// BillingStatement1 ...
type BillingStatement1 struct {
	StmtId      string                       `xml:"StmtId"`
	FrToDt      *DatePeriod1                 `xml:"FrToDt"`
	CreDtTm     string                       `xml:"CreDtTm"`
	Sts         string                       `xml:"Sts"`
	AcctChrtcs  *CashAccountCharacteristics1 `xml:"AcctChrtcs"`
	RateData    []*BillingRate1              `xml:"RateData"`
	CcyXchg     []*CurrencyExchange6         `xml:"CcyXchg"`
	Bal         []*BillingBalance1           `xml:"Bal"`
	Compstn     []*BillingCompensation1      `xml:"Compstn"`
	Svc         []*BillingService1           `xml:"Svc"`
	TaxRgn      []*BillingTaxRegion1         `xml:"TaxRgn"`
	BalAdjstmnt []*BalanceAdjustment1        `xml:"BalAdjstmnt"`
	SvcAdjstmnt []*BillingServiceAdjustment1 `xml:"SvcAdjstmnt"`
}

// BillingStatementStatus1Code ...
type BillingStatementStatus1Code string

// BillingSubServiceIdentification1 ...
type BillingSubServiceIdentification1 struct {
	Issr *BillingSubServiceQualifier1Choice `xml:"Issr"`
	Id   string                             `xml:"Id"`
}

// BillingSubServiceQualifier1Choice ...
type BillingSubServiceQualifier1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// BillingSubServiceQualifier1Code ...
type BillingSubServiceQualifier1Code string

// BillingTaxCalculationMethod1Code ...
type BillingTaxCalculationMethod1Code string

// BillingTaxIdentification1 ...
type BillingTaxIdentification1 struct {
	VATRegnNb string           `xml:"VATRegnNb"`
	TaxRegnNb string           `xml:"TaxRegnNb"`
	TaxCtct   *ContactDetails3 `xml:"TaxCtct"`
}

// BillingTaxRegion1 ...
type BillingTaxRegion1 struct {
	RgnNb       string                     `xml:"RgnNb"`
	RgnNm       string                     `xml:"RgnNm"`
	CstmrTaxId  string                     `xml:"CstmrTaxId"`
	PtDt        string                     `xml:"PtDt"`
	SndgFI      *BillingTaxIdentification1 `xml:"SndgFI"`
	InvcNb      string                     `xml:"InvcNb"`
	MtdC        *BillingMethod4            `xml:"MtdC"`
	SttlmAmt    *AmountAndDirection34      `xml:"SttlmAmt"`
	TaxDueToRgn *AmountAndDirection34      `xml:"TaxDueToRgn"`
}

// BranchAndFinancialInstitutionIdentification5 ...
type BranchAndFinancialInstitutionIdentification5 struct {
	FinInstnId *FinancialInstitutionIdentification8 `xml:"FinInstnId"`
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

// CashAccountCharacteristics1 ...
type CashAccountCharacteristics1 struct {
	AcctLvl      string                                        `xml:"AcctLvl"`
	CshAcct      *CashAccount16                                `xml:"CshAcct"`
	AcctSvcr     *BranchAndFinancialInstitutionIdentification5 `xml:"AcctSvcr"`
	PrntAcct     *ParentCashAccount1                           `xml:"PrntAcct"`
	CompstnMtd   string                                        `xml:"CompstnMtd"`
	DbtAcct      *AccountIdentification4Choice                 `xml:"DbtAcct"`
	DelydDbtDt   string                                        `xml:"DelydDbtDt"`
	SttlmAdvc    string                                        `xml:"SttlmAdvc"`
	AcctBalCcyCd string                                        `xml:"AcctBalCcyCd"`
	SttlmCcyCd   string                                        `xml:"SttlmCcyCd"`
	HstCcyCd     string                                        `xml:"HstCcyCd"`
	Tax          *AccountTax1                                  `xml:"Tax"`
	AcctSvcrCtct *ContactDetails3                              `xml:"AcctSvcrCtct"`
}

// CashAccountType2 ...
type CashAccountType2 struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// CashAccountType4Code ...
type CashAccountType4Code string

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

// CompensationMethod1Code ...
type CompensationMethod1Code string

// ContactDetails3 ...
type ContactDetails3 struct {
	NmPrfx    string           `xml:"NmPrfx"`
	Nm        string           `xml:"Nm"`
	PhneNb    string           `xml:"PhneNb"`
	MobNb     string           `xml:"MobNb"`
	FaxNb     string           `xml:"FaxNb"`
	EmailAdr  string           `xml:"EmailAdr"`
	Othr      []*OtherContact1 `xml:"Othr"`
	PrefrdMtd string           `xml:"PrefrdMtd"`
}

// CountryCode ...
type CountryCode string

// CurrencyExchange6 ...
type CurrencyExchange6 struct {
	SrcCcy   string  `xml:"SrcCcy"`
	TrgtCcy  string  `xml:"TrgtCcy"`
	XchgRate float64 `xml:"XchgRate"`
	Desc     string  `xml:"Desc"`
	UnitCcy  string  `xml:"UnitCcy"`
	Cmnts    string  `xml:"Cmnts"`
	QtnDt    string  `xml:"QtnDt"`
}

// DatePeriod1 ...
type DatePeriod1 struct {
	FrDt string `xml:"FrDt"`
	ToDt string `xml:"ToDt"`
}

// DecimalNumber ...
type DecimalNumber float64

// ExternalAccountIdentification1Code ...
type ExternalAccountIdentification1Code string

// ExternalBillingBalanceType1Code ...
type ExternalBillingBalanceType1Code string

// ExternalBillingCompensationType1Code ...
type ExternalBillingCompensationType1Code string

// ExternalBillingRateIdentification1Code ...
type ExternalBillingRateIdentification1Code string

// ExternalClearingSystemIdentification1Code ...
type ExternalClearingSystemIdentification1Code string

// ExternalFinancialInstitutionIdentification1Code ...
type ExternalFinancialInstitutionIdentification1Code string

// ExternalOrganisationIdentification1Code ...
type ExternalOrganisationIdentification1Code string

// FinancialIdentificationSchemeName1Choice ...
type FinancialIdentificationSchemeName1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// FinancialInstitutionIdentification8 ...
type FinancialInstitutionIdentification8 struct {
	BICFI       string                               `xml:"BICFI"`
	ClrSysMmbId *ClearingSystemMemberIdentification2 `xml:"ClrSysMmbId"`
	Nm          string                               `xml:"Nm"`
	PstlAdr     *PostalAddress6                      `xml:"PstlAdr"`
	Othr        *GenericFinancialIdentification1     `xml:"Othr"`
}

// FinancialInstitutionIdentification9 ...
type FinancialInstitutionIdentification9 struct {
	BICFI       string                               `xml:"BICFI"`
	ClrSysMmbId *ClearingSystemMemberIdentification2 `xml:"ClrSysMmbId"`
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

// IBAN2007Identifier ...
type IBAN2007Identifier string

// ISODate ...
type ISODate string

// ISODateTime ...
type ISODateTime string

// Max105Text ...
type Max105Text string

// Max10Text ...
type Max10Text string

// Max128Text ...
type Max128Text string

// Max12Text ...
type Max12Text string

// Max140Text ...
type Max140Text string

// Max16Text ...
type Max16Text string

// Max2048Text ...
type Max2048Text string

// Max20Text ...
type Max20Text string

// Max34Text ...
type Max34Text string

// Max35Text ...
type Max35Text string

// Max40Text ...
type Max40Text string

// Max4Text ...
type Max4Text string

// Max5NumericText ...
type Max5NumericText string

// Max6Text ...
type Max6Text string

// Max70Text ...
type Max70Text string

// Max8Text ...
type Max8Text string

// NamePrefix1Code ...
type NamePrefix1Code string

// Number ...
type Number float64

// OrganisationIdentification8 ...
type OrganisationIdentification8 struct {
	AnyBIC string                                `xml:"AnyBIC"`
	Othr   []*GenericOrganisationIdentification1 `xml:"Othr"`
}

// OrganisationIdentificationSchemeName1Choice ...
type OrganisationIdentificationSchemeName1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// OtherContact1 ...
type OtherContact1 struct {
	ChanlTp string `xml:"ChanlTp"`
	Id      string `xml:"Id"`
}

// Pagination ...
type Pagination struct {
	PgNb      string `xml:"PgNb"`
	LastPgInd bool   `xml:"LastPgInd"`
}

// ParentCashAccount1 ...
type ParentCashAccount1 struct {
	Lvl  string                                        `xml:"Lvl"`
	Id   *CashAccount16                                `xml:"Id"`
	Svcr *BranchAndFinancialInstitutionIdentification5 `xml:"Svcr"`
}

// Party13Choice ...
type Party13Choice struct {
	OrgId *OrganisationIdentification8         `xml:"OrgId"`
	FIId  *FinancialInstitutionIdentification9 `xml:"FIId"`
}

// PartyIdentification58 ...
type PartyIdentification58 struct {
	Nm        string           `xml:"Nm"`
	LglNm     string           `xml:"LglNm"`
	PstlAdr   *PostalAddress11 `xml:"PstlAdr"`
	Id        *Party13Choice   `xml:"Id"`
	CtryOfRes string           `xml:"CtryOfRes"`
	CtctDtls  *ContactDetails3 `xml:"CtctDtls"`
}

// PercentageRate ...
type PercentageRate float64

// PhoneNumber ...
type PhoneNumber string

// PlusOrMinusIndicator ...
type PlusOrMinusIndicator bool

// PostalAddress11 ...
type PostalAddress11 struct {
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
	Flr         string   `xml:"Flr"`
	PstBx       string   `xml:"PstBx"`
	BldgNm      string   `xml:"BldgNm"`
	Room        string   `xml:"Room"`
}

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

// PreferredContactMethod1Code ...
type PreferredContactMethod1Code string

// ReportHeader3 ...
type ReportHeader3 struct {
	RptId    string      `xml:"RptId"`
	MsgPgntn *Pagination `xml:"MsgPgntn"`
}

// ResidenceLocation1Choice ...
type ResidenceLocation1Choice struct {
	Ctry string `xml:"Ctry"`
	Area string `xml:"Area"`
}

// ServiceAdjustmentType1Code ...
type ServiceAdjustmentType1Code string

// ServicePaymentMethod1Code ...
type ServicePaymentMethod1Code string

// ServiceTaxDesignation1 ...
type ServiceTaxDesignation1 struct {
	Cd     string        `xml:"Cd"`
	Rgn    string        `xml:"Rgn"`
	TaxRsn []*TaxReason1 `xml:"TaxRsn"`
}

// ServiceTaxDesignation1Code ...
type ServiceTaxDesignation1Code string

// StatementGroup1 ...
type StatementGroup1 struct {
	GrpId        string                 `xml:"GrpId"`
	Sndr         *PartyIdentification58 `xml:"Sndr"`
	SndrIndvCtct []*ContactDetails3     `xml:"SndrIndvCtct"`
	Rcvr         *PartyIdentification58 `xml:"Rcvr"`
	RcvrIndvCtct []*ContactDetails3     `xml:"RcvrIndvCtct"`
	BllgStmt     []*BillingStatement1   `xml:"BllgStmt"`
}

// TaxCalculation1 ...
type TaxCalculation1 struct {
	HstCcy                string                    `xml:"HstCcy"`
	TaxblSvcChrgConvs     []*BillingServicesAmount3 `xml:"TaxblSvcChrgConvs"`
	TtlTaxblSvcChrgHstAmt *AmountAndDirection34     `xml:"TtlTaxblSvcChrgHstAmt"`
	TaxId                 []*BillingServicesTax3    `xml:"TaxId"`
	TtlTax                *AmountAndDirection34     `xml:"TtlTax"`
}

// TaxReason1 ...
type TaxReason1 struct {
	Cd     string `xml:"Cd"`
	Expltn string `xml:"Expltn"`
}

// YesNoIndicator ...
type YesNoIndicator bool
