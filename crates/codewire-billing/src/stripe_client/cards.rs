//! Saved cards (#4750): the customer's cards and its default, the
//! SetupIntents the console's card form confirms, and removing a card.

use super::*;

/// A card saved to an organization's Stripe customer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SavedCard {
    /// Stripe's PaymentMethod ID.
    pub id: String,
    /// `None` when Stripe's values are out of range (see [`CardSummary`]).
    pub card: Option<CardSummary>,
}

impl StripeHandle {
    /// The customer's saved cards, newest first, and its default's ID. More
    /// than one page (100 cards) is an explicit failure.
    pub async fn list_cards(
        &self,
        customer_id: &str,
    ) -> Result<(Vec<SavedCard>, Option<String>), AppError> {
        let client = self.client()?;
        let customer = customer_id
            .parse::<stripe_shared::CustomerId>()
            .map_err(stripe_err)?;
        let page = ListPaymentMethodsCustomer::new(customer.clone())
            .type_(ListPaymentMethodsCustomerType::Card)
            .limit(100)
            .send(client)
            .await
            .map_err(stripe_err)?;
        if page.has_more {
            return Err(AppError::InternalMsg(
                "a customer has more than 100 saved cards".into(),
            ));
        }
        let cards = page
            .data
            .iter()
            .map(|method| SavedCard {
                id: method.id.to_string(),
                card: method.card.as_ref().and_then(CardSummary::from_stripe),
            })
            .collect();
        let default = match RetrieveCustomer::new(customer).send(client).await {
            Ok(stripe_core::customer::RetrieveCustomerReturned::Customer(customer)) => customer
                .invoice_settings
                .and_then(|settings| settings.default_payment_method)
                .map(|method| match method {
                    stripe_types::Expandable::Id(id) => id.to_string(),
                    stripe_types::Expandable::Object(method) => method.id.to_string(),
                }),
            Ok(_) => None,
            Err(error) => return Err(stripe_err(error)),
        };
        Ok((cards, default))
    }

    /// A SetupIntent that saves one card to the customer for charges made
    /// later, while nobody is present: its client secret confirms the
    /// console's card form, and the bank's check happens in that form.
    /// `metadata` is written with the secret key, so neither the browser nor
    /// a link can change it.
    pub async fn create_card_setup_intent(
        &self,
        customer_id: &str,
        metadata: std::collections::HashMap<String, String>,
    ) -> Result<stripe_shared::SetupIntent, AppError> {
        let client = self.client()?;
        CreateSetupIntent::new()
            .customer(customer_id)
            .payment_method_types(vec!["card".to_string()])
            .usage(CreateSetupIntentUsage::OffSession)
            .metadata(metadata)
            .send(client)
            .await
            .map_err(stripe_err)
    }

    /// Adds `key` = `value` to a SetupIntent's metadata, keeping the rest.
    pub async fn add_setup_intent_metadata(
        &self,
        id: &str,
        key: &str,
        value: &str,
    ) -> Result<(), AppError> {
        let client = self.client()?;
        let _: stripe_shared::SetupIntent = UpdateSetupIntent::new(
            id.parse::<stripe_shared::SetupIntentId>()
                .map_err(stripe_err)?,
        )
        .metadata([(key.to_owned(), value.to_owned())])
        .send(client)
        .await
        .map_err(stripe_err)?;
        Ok(())
    }

    /// Detaches a saved card from its customer.
    pub async fn detach_card(&self, payment_method_id: &str) -> Result<(), AppError> {
        let client = self.client()?;
        let _: stripe_shared::PaymentMethod = RequestBuilder::new(
            StripeMethod::Post,
            format!("/payment_methods/{payment_method_id}/detach"),
        )
        .customize()
        .send(client)
        .await
        .map_err(stripe_err)?;
        Ok(())
    }

    pub async fn retrieve_setup_intent(
        &self,
        id: &str,
    ) -> Result<stripe_shared::SetupIntent, AppError> {
        let client = self.client()?;
        RetrieveSetupIntent::new(
            id.parse::<stripe_shared::SetupIntentId>()
                .map_err(stripe_err)?,
        )
        .send(client)
        .await
        .map_err(stripe_err)
    }

    /// Customer update setting invoice_settings.default_payment_method.
    pub async fn set_default_payment_method(
        &self,
        customer_id: &str,
        payment_method_id: &str,
        idempotency_key: &str,
    ) -> Result<(), AppError> {
        let client = self.client()?;
        let settings = UpdateCustomerInvoiceSettings {
            default_payment_method: Some(payment_method_id.to_string()),
            ..Default::default()
        };
        let idempotency_key = IdempotencyKey::new(idempotency_key).map_err(stripe_err)?;
        UpdateCustomer::new(
            customer_id
                .parse::<stripe_shared::CustomerId>()
                .map_err(stripe_err)?,
        )
        .invoice_settings(settings)
        .customize()
        .request_strategy(RequestStrategy::Idempotent(idempotency_key))
        .send(client)
        .await
        .map_err(stripe_err)?;
        Ok(())
    }
}
