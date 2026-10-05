import EgoKit
import SwiftUI

struct MarketView: View {
    @EnvironmentObject private var app: AppModel
    @AppStorage("market.fiat") private var fiat = "USD"
    @State private var side: MarketSide = .sell
    @State private var offers: [OfferListing]?
    @State private var next: String?
    @State private var egocUsd: Double = 0
    @State private var problem: String?
    @State private var loadingMore = false

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Picker("Direction", selection: $side) {
                        Text("Buy EGOC").tag(MarketSide.sell)
                        Text("Sell EGOC").tag(MarketSide.buy)
                    }
                    .pickerStyle(.segmented)
                    Picker(side == .sell ? "Pay with" : "Get paid in", selection: $fiat) {
                        ForEach(Fiat.all) { Text("\($0.code) · \($0.name)").tag($0.code) }
                    }
                }
                if let problem {
                    Section { ProblemBanner(text: problem) }
                }
                Section {
                    if let offers {
                        if offers.isEmpty {
                            Text("Nobody is \(side == .sell ? "selling" : "buying") EGOC for \(fiat) yet.")
                                .foregroundStyle(Brand.muted)
                        }
                        ForEach(offers) { listing in
                            NavigationLink {
                                OfferDetailView(listing: listing, egocUsd: egocUsd, mine: listing.offer.maker == app.address)
                            } label: {
                                OfferRow(listing: listing, egocUsd: egocUsd, mine: listing.offer.maker == app.address)
                            }
                        }
                        if next != nil {
                            Button(loadingMore ? "Loading…" : "Show more offers") { Task { await loadMore() } }
                                .disabled(loadingMore)
                        }
                    } else {
                        HStack { Spacer(); ProgressView(); Spacer() }
                    }
                } header: {
                    Text(side == .sell ? "People selling EGOC" : "People buying EGOC")
                } footer: {
                    Text("Every trade locks the EGOC in escrow until the seller confirms the payment. Trading from the phone is coming; for now, open these offers in Ego Desktop with the same wallet.")
                }
            }
            .scrollContentBackground(.hidden)
            .screenBackground()
            .navigationTitle("P2P Market")
            .refreshable { await load() }
            .task(id: "\(side.rawValue)-\(fiat)") {
                offers = nil
                next = nil
                await load()
                while !Task.isCancelled {
                    try? await Task.sleep(for: .seconds(30))
                    if Task.isCancelled { break }
                    await load()
                }
            }
        }
    }

    private func load() async {
        let side = self.side
        let fiat = self.fiat
        do {
            let price = try? await app.perform { try await $0.egocPriceUsd() }
            let page = try await app.perform { try await $0.marketOffers(fiat: fiat, side: side) }
            guard !Task.isCancelled, side == self.side, fiat == self.fiat else { return }
            if let price { egocUsd = price }
            offers = page.offers.filter(\.open)
            next = page.next
            problem = nil
        } catch {
            guard !Task.isCancelled else { return }
            if offers == nil { offers = [] }
            problem = app.message(for: error)
        }
    }

    private func loadMore() async {
        guard let cursor = next else { return }
        let side = self.side
        let fiat = self.fiat
        loadingMore = true
        defer { loadingMore = false }
        do {
            let page = try await app.perform { try await $0.marketOffers(fiat: fiat, side: side, cursor: cursor) }
            guard side == self.side, fiat == self.fiat else { return }
            let seen = Set((offers ?? []).map(\.id))
            offers = (offers ?? []) + page.offers.filter { $0.open && !seen.contains($0.id) }
            next = page.next
            problem = nil
        } catch {
            problem = app.message(for: error)
        }
    }
}

private func unitPriceText(_ offer: MarketOffer, egocUsd: Double) -> String {
    offer.price.unitMicro(fiat: offer.fiat, egocUsd: egocUsd).map { Fiat.formatUnitPrice(micro: $0, code: offer.fiat) } ?? "—"
}

struct OfferRow: View {
    let listing: OfferListing
    let egocUsd: Double
    let mine: Bool

    var body: some View {
        let offer = listing.offer
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .firstTextBaseline) {
                Text(unitPriceText(offer, egocUsd: egocUsd))
                    .font(.system(.headline, design: .rounded))
                    .foregroundStyle(Brand.text)
                Text(offer.price.marginLabel ?? "Fixed price")
                    .font(.caption2.weight(.semibold))
                    .foregroundStyle(Brand.mint)
                Spacer()
                if mine {
                    Text("YOUR OFFER")
                        .font(.caption2.weight(.bold))
                        .foregroundStyle(Brand.lime)
                }
            }
            Text("\(Amount.format(offer.minMicro, maxDecimals: 2)) – \(Amount.format(offer.maxMicro, maxDecimals: 2)) EGOC · pay within \(paymentWindowLabel(seconds: offer.paymentWindowSecs))")
                .font(.caption)
                .foregroundStyle(Brand.muted)
            Text("\(shortAddress(offer.maker)) · \(listing.makerProfile.summary)")
                .font(.caption)
                .foregroundStyle(Brand.muted)
            if !offer.methods.isEmpty {
                Text(offer.methods.map(PaymentMethods.label).joined(separator: " · "))
                    .font(.caption2.weight(.semibold))
                    .foregroundStyle(Brand.lime)
            }
        }
        .padding(.vertical, 4)
    }
}

struct OfferDetailView: View {
    let listing: OfferListing
    let egocUsd: Double
    let mine: Bool

    var body: some View {
        let offer = listing.offer
        let profile = listing.makerProfile
        let buying = offer.side == .sell
        Form {
            Section("Price") {
                LabeledContent("Per EGOC", value: unitPriceText(offer, egocUsd: egocUsd))
                LabeledContent("Pricing", value: offer.price.marginLabel ?? "Fixed price")
                LabeledContent("Limits", value: "\(Amount.format(offer.minMicro)) – \(Amount.format(offer.maxMicro)) EGOC")
                LabeledContent("Pay within", value: paymentWindowLabel(seconds: offer.paymentWindowSecs))
                if let country = offer.country, !country.isEmpty {
                    LabeledContent("Country", value: country)
                }
            }
            Section("Payment methods") {
                ForEach(offer.methods, id: \.self) { Text(PaymentMethods.label($0)) }
            }
            if !offer.terms.isEmpty {
                Section(buying ? "Seller's terms" : "Buyer's terms") {
                    Text(offer.terms)
                        .textSelection(.enabled)
                }
            }
            Section(buying ? "Seller" : "Buyer") {
                LabeledContent("Address", value: shortAddress(offer.maker))
                LabeledContent("Record", value: profile.summary)
                LabeledContent("Feedback", value: "\(profile.positive) good · \(profile.neutral) neutral · \(profile.negative) bad")
                if profile.disputesLost > 0 {
                    LabeledContent("Disputes lost", value: "\(profile.disputesLost)")
                        .foregroundStyle(Brand.danger)
                }
            }
            Section {
                Text(mine
                     ? "This is your offer. Manage it in Ego Desktop."
                     : "To \(buying ? "buy from" : "sell to") this trader, open P2P Trade in Ego Desktop with the same wallet. Trading from the phone arrives in a later update.")
                    .font(.footnote)
                    .foregroundStyle(Brand.muted)
            }
        }
        .scrollContentBackground(.hidden)
        .screenBackground()
        .navigationTitle(buying ? "Buy EGOC" : "Sell EGOC")
        .navigationBarTitleDisplayMode(.inline)
    }
}
