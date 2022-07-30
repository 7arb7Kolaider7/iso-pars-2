package pacs

import (
	"encoding/xml"

	"github.com/yudaprama/iso20022/model"
)

type Document00400107 struct {
	XMLName xml.Name          `xml:"urn:iso:std:iso:20022:tech:xsd:pacs.004.001.07 Document"`
	Message *PaymentReturnV07 `xml:"PmtRtr"`
}

func (d *Document00400107) AddMessage() *PaymentReturnV07 {
	d.Message = new(PaymentReturnV07)
	return d.Message
}

// Scope
// The PaymentReturn message is sent by an agent to the previous agent in the payment chain to undo a payment previously settled.
// Usage
// The PaymentReturn message is exchanged between agents to return funds after settlement of credit transfer instructions (i.e. FIToFICustomerCreditTransfer message and FinancialInstitutionCreditTransfer message) or direct debit instructions (FIToFICustomerDirectDebit message).
// The PaymentReturn message should not be used between agents and non-financial institution customers. Non-financial institution customers will be informed about a debit or a credit on their account(s) through a BankToCustomerDebitCreditNotification message ('notification') and/or BankToCustomerAccountReport/BankToCustomerStatement message ('statement').
// The PaymentReturn message can be used to return single instructions or multiple instructions from one or different files.
// The PaymentReturn message can be used in domestic and cross-border scenarios.
// The PaymentReturn message refers to the original instruction(s) by means of references only or by means of references and a set of elements from the original instruction.
type PaymentReturnV07 struct {

	// Set of characteristics shared by all individual transactions included in the message.
	GroupHeader *model.GroupHeader72 `xml:"GrpHdr"`

	// Information concerning the original group of transactions, to which the message refers.
	OriginalGroupInformation *model.OriginalGroupHeader2 `xml:"OrgnlGrpInf,omitempty"`

	// Information concerning the original transactions, to which the return message refers.
	TransactionInformation []*model.PaymentTransaction76 `xml:"TxInf,omitempty"`

	// Additional information that cannot be captured in the structured elements and/or any other specific block.
	SupplementaryData []*model.SupplementaryData1 `xml:"SplmtryData,omitempty"`
}

func (p *PaymentReturnV07) AddGroupHeader() *model.GroupHeader72 {
	p.GroupHeader = new(model.GroupHeader72)
	return p.GroupHeader
}

func (p *PaymentReturnV07) AddOriginalGroupInformation() *model.OriginalGroupHeader2 {
	p.OriginalGroupInformation = new(model.OriginalGroupHeader2)
	return p.OriginalGroupInformation
}

func (p *PaymentReturnV07) AddTransactionInformation() *model.PaymentTransaction76 {
	newValue := new(model.PaymentTransaction76)
	p.TransactionInformation = append(p.TransactionInformation, newValue)
	return newValue
}

func (p *PaymentReturnV07) AddSupplementaryData() *model.SupplementaryData1 {
	newValue := new(model.SupplementaryData1)
	p.SupplementaryData = append(p.SupplementaryData, newValue)
	return newValue
}
