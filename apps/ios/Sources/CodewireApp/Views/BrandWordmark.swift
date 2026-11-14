#if canImport(SwiftUI)
import SwiftUI
#if canImport(UIKit)
import UIKit
#endif

/// The Codewire wordmark, the mark and the name in the brand typeface,
/// tinted with the current text colour so it reads in light and dark mode.
struct BrandWordmark: View {
    var height: CGFloat = 40

    var body: some View {
        #if canImport(UIKit)
        if let image = UIImage(named: "Wordmark", in: .module, with: nil) {
            Image(uiImage: image.withRenderingMode(.alwaysTemplate))
                .resizable()
                .scaledToFit()
                .frame(height: height)
                .foregroundStyle(.primary)
                .accessibilityLabel("Codewire")
        } else {
            fallback
        }
        #else
        fallback
        #endif
    }

    private var fallback: some View {
        Text("codewire")
            .font(.largeTitle)
            .fontWeight(.bold)
    }
}
#endif
