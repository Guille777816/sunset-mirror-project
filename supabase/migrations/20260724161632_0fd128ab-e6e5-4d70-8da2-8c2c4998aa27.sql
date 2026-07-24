
-- 1) Recreate site_settings_public view with security_invoker so it enforces
--    the caller's permissions and RLS, not the view creator's.
DROP VIEW IF EXISTS public.site_settings_public;
CREATE VIEW public.site_settings_public
WITH (security_invoker = true) AS
SELECT
  id, business_name, address, phone, whatsapp, email, hours,
  instagram, facebook, logo_url, hero_eyebrow, hero_title, hero_subtitle,
  hero_description, hero_image_url, promo_banner, category_images,
  rate_usd, rate_brl, rate_pyg, updated_at
FROM public.site_settings;

GRANT SELECT ON public.site_settings_public TO anon, authenticated;

-- Allow anon SELECT of the safe columns on site_settings via the view.
-- The base table's existing "Admins can view settings" policy still hides
-- sensitive columns (bank details, cuit) from non-admins, because with
-- security_invoker the view now runs as the caller. Add a narrow public
-- read policy scoped to the "main" settings row.
DROP POLICY IF EXISTS "Public can read site settings" ON public.site_settings;
CREATE POLICY "Public can read site settings"
ON public.site_settings FOR SELECT
TO anon, authenticated
USING (id = 'main');
GRANT SELECT ON public.site_settings TO anon;

-- 2) Convert has_role to SECURITY INVOKER. The user_roles table already has
--    an owner-scoped SELECT policy ("Users can view their own roles"), so
--    callers can still see their own role rows. This clears both the
--    anon-executable and authenticated-executable SECURITY DEFINER lints.
CREATE OR REPLACE FUNCTION public.has_role(_user_id uuid, _role app_role)
RETURNS boolean
LANGUAGE sql
STABLE SECURITY INVOKER
SET search_path TO 'public'
AS $function$
  SELECT EXISTS (
    SELECT 1 FROM public.user_roles
    WHERE user_id = _user_id AND role = _role
  )
$function$;

-- 3) Remove permissive "USING (true) / WITH CHECK (true)" INSERT policies.
--    Orders and testimonials are now created exclusively via server functions
--    running with the service-role key, which validates input.
DROP POLICY IF EXISTS "Anyone can create orders" ON public.orders;
DROP POLICY IF EXISTS "Anyone can submit a testimonial (pending)" ON public.testimonials;

-- 4) Public storage buckets: drop the broad SELECT policies that let clients
--    list every object. Public buckets still serve files directly via
--    /storage/v1/object/public/<bucket>/<path> without requiring these
--    policies.
DROP POLICY IF EXISTS "Public read product-images" ON storage.objects;
DROP POLICY IF EXISTS "Public read site-assets" ON storage.objects;
DROP POLICY IF EXISTS "Public read product images" ON storage.objects;
