-- Dev seed (SEED_DEV=true): the four demo sites the dev traffic simulator targets, and locations for the
-- RFC 5737 documentation ranges it uses as simulated client addresses. Idempotent.
INSERT INTO sites (name, domain_name, paranoia_level, inbound_threshold) VALUES
    ('Public API', 'api.domain.com', 2, 5),
    ('Storefront', 'shop.domain.com', 1, 5),
    ('Customer Portal', 'portal.domain.com', 2, 7),
    ('Marketing CMS', 'cms.domain.com', 1, 5)
ON CONFLICT (domain_name) DO NOTHING;
INSERT INTO correlation_settings (site_id) SELECT id FROM sites ON CONFLICT DO NOTHING;
INSERT INTO geoip_overrides (cidr, country_code, asn, as_name, lon, lat) VALUES
    ('192.0.2.0/25', 'NL', 64512, 'AS64512 Sample Hosting A', 4.90, 52.37),
    ('192.0.2.128/25', 'FR', 64513, 'AS64513 Sample Cloud B', 2.35, 48.86),
    ('198.51.100.0/25', 'BR', 64514, 'AS64514 Sample ISP C', -46.63, -23.55),
    ('198.51.100.128/25', 'SG', 64515, 'AS64515 Sample VPS D', 103.80, 1.30),
    ('203.0.113.0/25', 'CN', 64516, 'AS64516 Sample Net E', 116.40, 39.90),
    ('203.0.113.128/25', 'US', 64517, 'AS64517 Sample Cloud F', -122.33, 47.61)
ON CONFLICT (cidr) DO NOTHING;
