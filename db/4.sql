BEGIN EXCLUSIVE;

CREATE INDEX idx_sboms_repository_state_id ON sboms(repository_state_id);
CREATE INDEX idx_sboms_type ON sboms(type);
CREATE INDEX idx_sboms_origin_type ON sboms(origin_type);

CREATE INDEX idx_sbom_creators_creator_id ON sbom_creators(creator_id);
CREATE INDEX idx_repository_states_repository_id ON repository_states(repository_id);
CREATE INDEX idx_repository_languages_language_id ON repository_languages(language_id);

COMMIT;
