use cockpit_config::config::image_generation::*;

fn candidate(width: u64, height: u64, value: &str) -> ImageDimensionCandidate {
    ImageDimensionCandidate {
        width,
        height,
        provider_value: value.into(),
    }
}

#[test]
fn image_dimension_resolution_covers_descriptors_and_policies() {
    let discrete = ImageDimensionDescriptor::Discrete {
        candidates: vec![candidate(512, 512, "square"), candidate(1024, 512, "wide")],
    };
    assert_eq!(
        discrete
            .resolve(ImageDimensionRequestPolicy::Exact, Some(512), Some(512))
            .unwrap(),
        ImageDimensionResolution::Resolved(candidate(512, 512, "square"))
    );
    assert!(
        matches!(discrete.resolve(ImageDimensionRequestPolicy::Exact, Some(600), Some(600)).unwrap(), ImageDimensionResolution::Unsupported { alternatives } if alternatives.len() == 2)
    );
    assert_eq!(
        discrete
            .resolve(ImageDimensionRequestPolicy::Nearest, Some(700), Some(700))
            .unwrap(),
        ImageDimensionResolution::Resolved(candidate(512, 512, "square"))
    );

    let range = ImageDimensionDescriptor::RangeStep {
        min_width: 256,
        max_width: 1024,
        width_step: 256,
        min_height: 256,
        max_height: 1024,
        height_step: 256,
        provider_value_format: RangeProviderValueFormat::WidthXHeight,
    };
    assert!(matches!(
        range
            .resolve(ImageDimensionRequestPolicy::Exact, Some(512), Some(768))
            .unwrap(),
        ImageDimensionResolution::Resolved(_)
    ));
    assert!(matches!(
        range
            .resolve(ImageDimensionRequestPolicy::Exact, Some(513), Some(768))
            .unwrap(),
        ImageDimensionResolution::Unsupported { alternatives } if !alternatives.is_empty()
    ));
    assert!(
        matches!(range.resolve(ImageDimensionRequestPolicy::Nearest, Some(513), Some(770)).unwrap(), ImageDimensionResolution::Resolved(value) if value.width == 512 && value.height == 768)
    );
    assert!(matches!(
        range.resolve(ImageDimensionRequestPolicy::Exact, None, None).unwrap(),
        ImageDimensionResolution::Unsupported { alternatives } if !alternatives.is_empty()
    ));

    let aspect_first = ImageDimensionDescriptor::RangeStep {
        min_width: 100,
        max_width: 1_000,
        width_step: 100,
        min_height: 100,
        max_height: 1_000,
        height_step: 100,
        provider_value_format: RangeProviderValueFormat::WidthXHeight,
    };
    assert!(matches!(
        aspect_first.resolve(ImageDimensionRequestPolicy::Nearest, Some(250), Some(1_000)).unwrap(),
        ImageDimensionResolution::Resolved(value) if value.width == 200 && value.height == 800
    ));

    assert_eq!(
        ImageDimensionDescriptor::ProviderDefault
            .resolve(ImageDimensionRequestPolicy::Exact, None, None)
            .unwrap(),
        ImageDimensionResolution::ProviderDefault
    );
    assert_eq!(
        ImageDimensionDescriptor::Unknown
            .resolve(ImageDimensionRequestPolicy::Exact, Some(1), Some(1))
            .unwrap(),
        ImageDimensionResolution::Unknown
    );
    assert_eq!(
        discrete
            .resolve(
                ImageDimensionRequestPolicy::ProviderDefault,
                Some(1),
                Some(1)
            )
            .unwrap(),
        ImageDimensionResolution::ProviderDefault
    );
}

#[test]
fn image_dimension_nearest_ties_are_deterministic() {
    // Equal aspect error, then equal pixel delta, then lower pixels, then
    // lexical provider value.
    let descriptor = ImageDimensionDescriptor::AspectTier {
        tiers: vec![candidate(800, 800, "z"), candidate(600, 600, "a")],
    };
    assert_eq!(
        descriptor
            .resolve(ImageDimensionRequestPolicy::Nearest, Some(700), Some(700))
            .unwrap(),
        ImageDimensionResolution::Resolved(candidate(600, 600, "a"))
    );
    let lexical = ImageDimensionDescriptor::Discrete {
        candidates: vec![candidate(512, 512, "z"), candidate(512, 512, "a")],
    };
    assert_eq!(
        lexical
            .resolve(ImageDimensionRequestPolicy::Nearest, Some(500), Some(500))
            .unwrap(),
        ImageDimensionResolution::Resolved(candidate(512, 512, "a"))
    );
}

#[test]
fn image_dimension_resolution_checks_boundaries_and_overflow() {
    let descriptor = ImageDimensionDescriptor::RangeStep {
        min_width: 1,
        max_width: 10_000,
        width_step: 1,
        min_height: 1,
        max_height: 10_000,
        height_step: 1,
        provider_value_format: RangeProviderValueFormat::WidthXHeight,
    };
    assert!(matches!(
        descriptor
            .resolve(ImageDimensionRequestPolicy::Exact, Some(1), Some(1))
            .unwrap(),
        ImageDimensionResolution::Resolved(_)
    ));
    assert!(matches!(
        descriptor
            .resolve(
                ImageDimensionRequestPolicy::Exact,
                Some(10_000),
                Some(10_000)
            )
            .unwrap(),
        ImageDimensionResolution::Resolved(_)
    ));
    assert!(
        descriptor
            .resolve(ImageDimensionRequestPolicy::Exact, Some(u64::MAX), Some(2))
            .is_err()
    );
    assert_eq!(
        descriptor
            .resolve(ImageDimensionRequestPolicy::Exact, Some(u64::MAX), Some(2))
            .unwrap_err(),
        ImageGenerationConfigError::ArithmeticOverflow
    );
    for invalid in [
        ImageDimensionDescriptor::Discrete { candidates: vec![] },
        ImageDimensionDescriptor::RangeStep {
            min_width: 2,
            max_width: 1,
            width_step: 1,
            min_height: 1,
            max_height: 1,
            height_step: 1,
            provider_value_format: RangeProviderValueFormat::WidthXHeight,
        },
        ImageDimensionDescriptor::RangeStep {
            min_width: 1,
            max_width: 2,
            width_step: 0,
            min_height: 1,
            max_height: 2,
            height_step: 1,
            provider_value_format: RangeProviderValueFormat::WidthXHeight,
        },
    ] {
        assert_eq!(
            invalid
                .resolve(ImageDimensionRequestPolicy::Exact, Some(1), Some(1))
                .unwrap_err(),
            ImageGenerationConfigError::InvalidDimensions
        );
    }
}
