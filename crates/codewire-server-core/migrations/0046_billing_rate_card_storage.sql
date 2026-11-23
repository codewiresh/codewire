-- A storage rate on every rate card (#5782, docs/dev/BILLING.md "Prices").
--
-- billing_rate_cards.parked_storage_nano_eur_per_gib_hour: what a card
-- charges per GiB-hour of disk for a Sandbox that is suspended or
-- hibernated, in nano-euros like the card's other rates. 0 on every card,
-- existing and new, so no price changes here: only a platform administrator
-- sets one.
--
-- Unlimited charges nothing at any of its four rates, so its check is
-- replaced by one that also names the storage rate.
--
-- Every rate is at most EUR 10 per unit-hour (10000000000 nano-euros), about
-- 228 times Regular's vCPU-hour, so a mistyped price can't reprice every
-- organization or overflow a draw. Every card is far below it.
--
-- Compatible: adding a column with a constant default rewrites no rows, and
-- older code that does not read it keeps working; every card already passes
-- the wider check.
--
-- Rollback: drop the upper-bound check and the column, which drops both
-- checks that name it, and add the earlier three-rate Unlimited check back.
ALTER TABLE ONLY public.billing_rate_cards
    ADD COLUMN parked_storage_nano_eur_per_gib_hour bigint DEFAULT 0 NOT NULL,
    ADD CONSTRAINT billing_rate_cards_parked_storage_rate_check
        CHECK (parked_storage_nano_eur_per_gib_hour >= 0),
    ADD CONSTRAINT billing_rate_cards_rates_upper_bound_check CHECK (
        cpu_nano_eur_per_vcpu_hour <= 10000000000
        AND memory_nano_eur_per_gib_hour <= 10000000000
        AND disk_nano_eur_per_gib_hour <= 10000000000
        AND parked_storage_nano_eur_per_gib_hour <= 10000000000
    ),
    DROP CONSTRAINT billing_rate_cards_unlimited_charges_nothing_check,
    ADD CONSTRAINT billing_rate_cards_unlimited_charges_nothing_check CHECK (
        rate_card <> 'unlimited'
        OR (cpu_nano_eur_per_vcpu_hour = 0
            AND memory_nano_eur_per_gib_hour = 0
            AND disk_nano_eur_per_gib_hour = 0
            AND parked_storage_nano_eur_per_gib_hour = 0)
    );
